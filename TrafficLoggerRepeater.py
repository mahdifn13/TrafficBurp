# -*- coding: utf-8 -*-
"""
Traffic Logger + Repeater Sender  (v3)
---------------------------------------
Burp Suite extension (Jython) that:
  1. Does NOT capture traffic live. Instead it reads (pulls) from Burp's own
     Proxy History whenever you click "Sync Now" or when auto-save fires.
  2. Requires YOU to choose a log file path first (button in the UI) --
     nothing is auto-saved anywhere until you pick a location.
  3. Auto-saves / auto-syncs on a user-configurable timer (default: 10 min).
  4. Sends selected entries to Repeater. If the entry has a comment, that
     comment becomes the Repeater tab title; otherwise the title is blank.
  5. Filters what gets pulled in: Save All / In-Scope Only (Burp Target Scope) /
     Custom domain list. Duplicate requests are always skipped automatically.
  6. Lets you highlight rows with a color; highlights persist across reloads.
  7. Has a search box that filters the table live against the FULL raw
     request (URL, query params, headers, body) -- not just the URL column.
     Great for finding "which request had this parameter/value in it".

Requirements:
  - Jython standalone JAR configured under:
      Extender -> Options -> Python Environment -> Location of Jython standalone JAR
    (https://www.jython.org/download)

Install:
  Extender -> Extensions -> Add -> Extension type: Python -> select this file.

On first use:
  Click "Choose Log File..." at the top of the Traffic tab and pick (or create)
  a file, e.g. traffic_log.jsonl. Everything else (auto-save, Sync Now, Save Now)
  is disabled until you do this.
"""

from burp import IBurpExtender
from burp import ITab

from javax.swing import (JPanel, JTable, JScrollPane, JButton, JLabel,
                          JOptionPane, JFileChooser,
                          JSpinner, SpinnerNumberModel, JCheckBox, JRadioButton,
                          ButtonGroup, JTextField, JPopupMenu, JMenuItem, JMenu,
                          Timer, JDialog, BoxLayout, SwingUtilities)
from javax.swing.border import EmptyBorder
from javax.swing.event import DocumentListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, FlowLayout, Color, GridLayout
from java.awt.event import MouseAdapter
from java.io import File, FileWriter, BufferedWriter, FileReader, BufferedReader
from java.net import URL as JURL
from java.util import Base64

import json
import time
import os
import hashlib


COLUMN_NAMES = ["#", "Time", "Method", "Host", "URL", "Status", "Highlight", "Comment"]

HIGHLIGHT_COLORS = {
    "NONE": None,
    "RED": Color(219, 26, 15),
    "ORANGE": Color(230, 111, 7),
    "YELLOW": Color(240, 212, 2),
    "GREEN": Color(65, 209, 25),
    "CYAN": Color(200, 255, 255),
    "PINK": Color(240, 2, 200),
    "GRAY": Color(153, 150, 152),
}


class HighlightRenderer(DefaultTableCellRenderer):
    """Colors an entire row based on the entry's stored highlight."""
    def __init__(self, extender):
        self._extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        try:
            model_row = table.convertRowIndexToModel(row)
            idx = int(table.getModel().getValueAt(model_row, 0))
            entry = self._extender.get_entry_by_index(idx)
            color_name = entry.get("highlight", "NONE") if entry else "NONE"
            bg = HIGHLIGHT_COLORS.get(color_name)
            if isSelected:
                comp.setBackground(table.getSelectionBackground())
            elif bg is not None:
                comp.setBackground(bg)
            else:
                comp.setBackground(table.getBackground())
        except Exception:
            pass
        return comp


class SearchDocumentListener(DocumentListener):
    """Calls the given no-arg callback on every keystroke in the search field."""
    def __init__(self, callback):
        self._callback = callback

    def insertUpdate(self, e):
        self._callback()

    def removeUpdate(self, e):
        self._callback()

    def changedUpdate(self, e):
        self._callback()


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Traffic Logger + Repeater Sender")

        self._entries = []          # list of dict entries, in pull order
        self._entries_by_index = {}
        self._seen_hashes = set()   # for dedupe (always on)
        self._last_synced_history_count = 0  # fast-skip: index up to which history was already scanned
        self._autosave_timer = None

        self._log_file_path = None    # user must choose this

        self._build_ui()

        callbacks.addSuiteTab(self)

        print("[TrafficLogger] Loaded. Choose a log file path in the Traffic tab to begin.")

    # ---------------------------------------------------------------
    # UI construction
    # ---------------------------------------------------------------
    def _build_ui(self):
        self._build_traffic_tab()
        self._root = self._traffic_panel

    def _build_traffic_tab(self):
        self._traffic_panel = JPanel(BorderLayout())

        top = JPanel()
        top.setLayout(GridLayout(2, 1))

        # Top bar: log file path + status + settings entry point
        path_row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        path_row.add(JLabel("Log:"))
        self._path_field = JTextField("(not set)", 40)
        self._path_field.setEditable(False)
        path_row.add(self._path_field)
        choose_btn = JButton("Choose Log File...", actionPerformed=self._on_choose_log_path)
        path_row.add(choose_btn)
        self._autosave_status_lbl = JLabel("choose a log file path first")
        path_row.add(self._autosave_status_lbl)
        settings_btn = JButton("Settings...", actionPerformed=self._on_open_settings)
        path_row.add(settings_btn)

        # Search bar -- the main day-to-day control, so it gets its own
        # full-width row instead of being buried among other options.
        search_row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        search_row.add(JLabel("Search (params / headers / body / anything):"))
        self._search_field = JTextField(35)
        search_row.add(self._search_field)
        clear_search_btn = JButton("Clear", actionPerformed=self._on_clear_search)
        search_row.add(clear_search_btn)
        self._search_match_lbl = JLabel("")
        search_row.add(self._search_match_lbl)
        self._search_field.getDocument().addDocumentListener(
            SearchDocumentListener(lambda: self._rebuild_table()))

        top.add(path_row)
        top.add(search_row)

        # Table
        self._table_model = DefaultTableModel(COLUMN_NAMES, 0)
        self._table = JTable(self._table_model)
        self._table.setAutoCreateRowSorter(True)
        self._table.setToolTipText("Right-click a row for Highlight / Comment / Delete")
        renderer = HighlightRenderer(self)
        for col in range(len(COLUMN_NAMES)):
            self._table.getColumnModel().getColumn(col).setCellRenderer(renderer)
        self._table.addMouseListener(self._make_context_menu_listener())
        scroll = JScrollPane(self._table)

        # Bottom action toolbar -- the buttons you actually click day to day
        bottom = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        send_btn = JButton("Send to Repeater", actionPerformed=self._on_send_to_repeater)
        sync_btn = JButton("Sync Now", actionPerformed=self._on_sync_now)
        save_btn = JButton("Save Now", actionPerformed=self._on_save_now)
        save_as_btn = JButton("Export...", actionPerformed=self._on_save_as)
        load_btn = JButton("Load...", actionPerformed=self._on_load_from_file)
        clear_btn = JButton("Clear Table", actionPerformed=self._on_clear)
        bottom.add(send_btn)
        bottom.add(sync_btn)
        bottom.add(save_btn)
        bottom.add(save_as_btn)
        bottom.add(load_btn)
        bottom.add(clear_btn)

        self._traffic_panel.add(top, BorderLayout.NORTH)
        self._traffic_panel.add(scroll, BorderLayout.CENTER)
        self._traffic_panel.add(bottom, BorderLayout.SOUTH)

        self._build_settings_controls()  # creates the widgets used inside the dialog

    def _build_settings_controls(self):
        """Creates the autosave/scope controls used by the Settings dialog.
        Kept separate from the dialog itself so the dialog can be built lazily."""
        self._autosave_enabled_cb = JCheckBox("Enable auto-sync + auto-save every", True)
        self._autosave_spinner = JSpinner(SpinnerNumberModel(10, 1, 240, 1))  # default 10 min
        self._autosave_enabled_cb.addActionListener(lambda e: self._restart_autosave_timer())
        self._autosave_spinner.addChangeListener(lambda e: self._restart_autosave_timer())

        self._scope_all_rb = JRadioButton("Save all", True)
        self._scope_burp_rb = JRadioButton("In-scope only (Burp target scope)")
        self._scope_custom_rb = JRadioButton("Custom domains:")
        group = ButtonGroup()
        group.add(self._scope_all_rb)
        group.add(self._scope_burp_rb)
        group.add(self._scope_custom_rb)
        self._custom_domains_field = JTextField("google.com, *.google.com", 22)

    def _on_open_settings(self, event):
        owner_window = SwingUtilities.getWindowAncestor(self._traffic_panel)
        dialog = JDialog(owner_window, "Settings", True)
        dialog.setLayout(BorderLayout())

        content = JPanel()
        content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
        content.setBorder(EmptyBorder(14, 14, 14, 14))

        autosave_section = JPanel(FlowLayout(FlowLayout.LEFT))
        autosave_section.add(self._autosave_enabled_cb)
        autosave_section.add(self._autosave_spinner)
        autosave_section.add(JLabel("minutes"))
        content.add(autosave_section)

        content.add(JLabel(" "))
        content.add(JLabel("Pull scope:"))
        scope_all_row = JPanel(FlowLayout(FlowLayout.LEFT))
        scope_all_row.add(self._scope_all_rb)
        content.add(scope_all_row)
        scope_burp_row = JPanel(FlowLayout(FlowLayout.LEFT))
        scope_burp_row.add(self._scope_burp_rb)
        content.add(scope_burp_row)
        scope_custom_row = JPanel(FlowLayout(FlowLayout.LEFT))
        scope_custom_row.add(self._scope_custom_rb)
        scope_custom_row.add(self._custom_domains_field)
        content.add(scope_custom_row)

        content.add(JLabel(" "))
        content.add(JLabel("Duplicates are always skipped automatically."))

        close_row = JPanel(FlowLayout(FlowLayout.RIGHT))
        close_btn = JButton("Close", actionPerformed=lambda e: dialog.dispose())
        close_row.add(close_btn)

        dialog.add(content, BorderLayout.CENTER)
        dialog.add(close_row, BorderLayout.SOUTH)
        dialog.pack()
        dialog.setLocationRelativeTo(owner_window)
        dialog.setVisible(True)

    def getTabCaption(self):
        return "Traffic Logger"

    def getUiComponent(self):
        return self._root

    # ---------------------------------------------------------------
    # Log file path selection (required first step)
    # ---------------------------------------------------------------
    def _on_choose_log_path(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Choose or create a log file")
        chooser.setSelectedFile(File("burp_traffic_log.jsonl"))
        result = chooser.showDialog(self._traffic_panel, "Select")
        if result != JFileChooser.APPROVE_OPTION:
            return

        path = chooser.getSelectedFile().getAbsolutePath()
        self._log_file_path = path
        self._path_field.setText(path)

        if os.path.exists(path):
            load_it = JOptionPane.showConfirmDialog(
                self._traffic_panel,
                "This file already has data. Load existing entries from it?",
                "Load existing log?", JOptionPane.YES_NO_OPTION)
            if load_it == JOptionPane.YES_OPTION:
                self._load_from_disk(path)
        else:
            self._entries = []
            self._entries_by_index = {}
            self._seen_hashes = set()
            self._table_model.setRowCount(0)

        # New log file = new "session" for sync purposes. Without this reset,
        # switching to a fresh/empty log file would silently skip re-scanning
        # Proxy History items that were already scanned under a previous path.
        self._last_synced_history_count = 0

        self._restart_autosave_timer()
        JOptionPane.showMessageDialog(self._traffic_panel, "Log file set to:\n%s" % path)

    def _require_path(self, action_description):
        if self._log_file_path is None:
            JOptionPane.showMessageDialog(
                self._traffic_panel,
                "Choose a log file path first (button at the top) before %s." % action_description)
            return False
        return True

    # ---------------------------------------------------------------
    # Context menu (right click): Highlight / Comment / Delete / Send
    # ---------------------------------------------------------------
    def _make_context_menu_listener(self):
        extender = self

        class Listener(MouseAdapter):
            def mousePressed(self, e):
                self._maybe_show(e)

            def mouseReleased(self, e):
                self._maybe_show(e)

            def _maybe_show(self, e):
                if e.isPopupTrigger():
                    row = extender._table.rowAtPoint(e.getPoint())
                    if row >= 0:
                        extender._table.setRowSelectionInterval(row, row)
                        extender._show_context_menu(e.getComponent(), e.getX(), e.getY())

        return Listener()

    def _show_context_menu(self, component, x, y):
        entry = self._selected_entry()
        if entry is None:
            return
        menu = JPopupMenu()

        send_item = JMenuItem("Send to Repeater", actionPerformed=self._on_send_to_repeater)
        menu.add(send_item)
        menu.addSeparator()

        highlight_menu = JMenu("Highlight")
        for color_name in ["NONE", "RED", "ORANGE", "YELLOW", "GREEN", "CYAN", "PINK", "GRAY"]:
            item = JMenuItem(color_name)
            item.addActionListener(self._make_highlight_action(color_name))
            highlight_menu.add(item)
        menu.add(highlight_menu)

        comment_item = JMenuItem("Add / Edit Comment...", actionPerformed=self._on_edit_comment)
        menu.add(comment_item)

        menu.addSeparator()
        delete_item = JMenuItem("Delete Entry", actionPerformed=self._on_delete_entry)
        menu.add(delete_item)

        menu.show(component, x, y)

    def _make_highlight_action(self, color_name):
        def action(event):
            entry = self._selected_entry()
            if entry is None:
                return
            entry["highlight"] = color_name
            self._rebuild_table()
        return action

    def _on_edit_comment(self, event):
        entry = self._selected_entry()
        if entry is None:
            return
        current = entry.get("comment", "")
        new_comment = JOptionPane.showInputDialog(
            self._traffic_panel, "Comment for %s %s:" % (entry.get("method", ""), entry.get("url", "")),
            current)
        if new_comment is not None:
            entry["comment"] = new_comment
            self._rebuild_table()

    def _on_delete_entry(self, event):
        entry = self._selected_entry()
        if entry is None:
            return
        confirm = JOptionPane.showConfirmDialog(
            self._traffic_panel, "Delete this entry from the table?", "Confirm",
            JOptionPane.YES_NO_OPTION)
        if confirm == JOptionPane.YES_OPTION:
            self._entries.remove(entry)
            del self._entries_by_index[entry["index"]]
            self._rebuild_table()

    def _rebuild_table(self):
        query = ""
        try:
            query = self._search_field.getText().strip().lower()
        except Exception:
            pass

        self._table_model.setRowCount(0)
        shown = 0
        for entry in self._entries:
            if query and query not in self._get_searchable_text(entry):
                continue
            shown += 1
            self._table_model.addRow([entry["index"], entry.get("time", ""),
                                       entry.get("method", ""), entry.get("host", ""),
                                       entry.get("url", ""), entry.get("status", ""),
                                       entry.get("highlight", "NONE"), entry.get("comment", "")])

        try:
            if query:
                self._search_match_lbl.setText("  %d / %d match" % (shown, len(self._entries)))
            else:
                self._search_match_lbl.setText("")
        except Exception:
            pass

    def _get_searchable_text(self, entry):
        """Lazily decode+cache the full raw request as lowercase text for searching.
        This covers the URL, query params, headers, and body -- everything.
        The cache key starts with '_' so it's stripped before writing to disk."""
        cached = entry.get("_decoded_lower")
        if cached is not None:
            return cached
        try:
            raw_bytes = self._b64_to_bytes(entry.get("request_b64", ""))
            text = self._helpers.bytesToString(raw_bytes)
        except Exception:
            text = entry.get("url", "")
        text_lower = (text + "\n" + entry.get("comment", "")).lower()
        entry["_decoded_lower"] = text_lower
        return text_lower

    def _on_clear_search(self, event):
        self._search_field.setText("")
        self._rebuild_table()

    # ---------------------------------------------------------------
    # Pull traffic from Burp's Proxy History (no live capture)
    # ---------------------------------------------------------------
    def _sync_from_history(self, silent=False):
        try:
            history = self._callbacks.getProxyHistory()
            total = len(history)

            # Speed: only look at items we haven't scanned before. Burp's proxy
            # history is append-only, so anything before this index was already
            # handled on a previous sync.
            start_index = self._last_synced_history_count
            if start_index > total:
                start_index = 0  # history was somehow shorter (e.g. new Burp session) - rescan

            imported = 0
            for i in range(start_index, total):
                messageInfo = history[i]
                before = len(self._entries)
                self._process_history_item(messageInfo)
                if len(self._entries) > before:
                    imported += 1

            self._last_synced_history_count = total

            if imported > 0:
                self._rebuild_table()  # re-apply current search filter to the new items too

            if not silent:
                JOptionPane.showMessageDialog(
                    self._traffic_panel,
                    "Pulled %d new item(s) from Proxy History (scanned %d new, skipped %d already-seen)."
                    % (imported, total - start_index, start_index))
            return imported
        except Exception as e:
            if not silent:
                JOptionPane.showMessageDialog(self._traffic_panel, "Sync failed: %s" % str(e))
            print("[TrafficLogger] Sync failed: %s" % str(e))
            return 0

    def _process_history_item(self, messageInfo):
        http_service = messageInfo.getHttpService()
        host = http_service.getHost()
        port = http_service.getPort()
        protocol = http_service.getProtocol()

        request_bytes = messageInfo.getRequest()
        response_bytes = messageInfo.getResponse()

        request_info = self._helpers.analyzeRequest(messageInfo)
        method = request_info.getMethod()
        url = str(request_info.getUrl())

        if not self._passes_scope_filter(url, host):
            return

        # Dedupe is always on now -- never save the same request twice, regardless
        # of any UI toggle. This is what stops "Sync Now" / auto-sync from piling
        # up duplicate copies of items it has already logged.
        dedupe_key = self._make_dedupe_key(method, url, request_bytes)
        if dedupe_key in self._seen_hashes:
            return
        self._seen_hashes.add(dedupe_key)

        status = ""
        if response_bytes is not None:
            response_info = self._helpers.analyzeResponse(response_bytes)
            status = str(response_info.getStatusCode())

        entry = {
            "index": len(self._entries),
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "method": method,
            "host": host,
            "port": port,
            "protocol": protocol,
            "url": url,
            "status": status,
            "request_b64": self._bytes_to_b64(request_bytes),
            "highlight": "NONE",
            "comment": "",
            "dedupe_key": dedupe_key,
        }

        self._entries.append(entry)
        self._entries_by_index[entry["index"]] = entry
        # Note: no direct addRow here anymore -- _sync_from_history calls
        # _rebuild_table() once after the whole batch so the search filter
        # is applied consistently to newly-pulled items too.

    def get_entry_by_index(self, idx):
        return self._entries_by_index.get(idx)

    # ---------------------------------------------------------------
    # Scope filter + dedupe helpers
    # ---------------------------------------------------------------
    def _passes_scope_filter(self, url, host):
        if self._scope_all_rb.isSelected():
            return True
        elif self._scope_burp_rb.isSelected():
            try:
                return self._callbacks.isInScope(JURL(url))
            except Exception:
                return False
        elif self._scope_custom_rb.isSelected():
            raw = self._custom_domains_field.getText()
            domains = [d.strip().lower().lstrip("*.") for d in raw.split(",") if d.strip()]
            host_lower = host.lower()
            for d in domains:
                if host_lower == d or host_lower.endswith("." + d):
                    return True
            return False
        return True

    def _make_dedupe_key(self, method, url, request_bytes):
        try:
            body = bytes(request_bytes) if request_bytes else b""
        except Exception:
            body = str(request_bytes)
        h = hashlib.sha256()
        h.update(str(method))
        h.update(str(url))
        try:
            h.update(str(body))
        except Exception:
            pass
        return h.hexdigest()

    # ---------------------------------------------------------------
    # Encoding helpers
    # ---------------------------------------------------------------
    def _bytes_to_b64(self, data):
        if data is None:
            return ""
        return str(Base64.getEncoder().encodeToString(data))

    def _b64_to_bytes(self, b64_str):
        return Base64.getDecoder().decode(b64_str)

    # ---------------------------------------------------------------
    # Persistence (all relative to the user-chosen self._log_file_path)
    # ---------------------------------------------------------------
    def _flush_all_to_disk(self):
        if self._log_file_path is None:
            return
        try:
            tmp_path = self._log_file_path + ".tmp"
            f = FileWriter(tmp_path, False)
            bw = BufferedWriter(f)
            for entry in self._entries:
                bw.write(json.dumps(self._serializable_entry(entry)))
                bw.newLine()
            bw.close()
            f.close()
            if os.path.exists(self._log_file_path):
                os.remove(self._log_file_path)
            os.rename(tmp_path, self._log_file_path)
        except Exception as e:
            print("[TrafficLogger] Failed to flush log: %s" % str(e))

    def _serializable_entry(self, entry):
        """Strip runtime-only cache keys (e.g. the search-text cache) before writing to disk."""
        return dict((k, v) for k, v in entry.items() if not k.startswith("_"))

    def _load_from_disk(self, path):
        if not os.path.exists(path):
            return
        try:
            fr = FileReader(path)
            br = BufferedReader(fr)
            line = br.readLine()
            while line is not None:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        entry["index"] = len(self._entries)
                        entry.setdefault("highlight", "NONE")
                        entry.setdefault("comment", "")
                        self._entries.append(entry)
                        self._entries_by_index[entry["index"]] = entry
                        if "dedupe_key" in entry:
                            self._seen_hashes.add(entry["dedupe_key"])
                    except Exception:
                        pass
                line = br.readLine()
            br.close()
            fr.close()
            self._rebuild_table()
            print("[TrafficLogger] Loaded %d entries from %s" % (len(self._entries), path))
        except Exception as e:
            print("[TrafficLogger] Failed to load log: %s" % str(e))

    # ---------------------------------------------------------------
    # Auto-sync + auto-save timer
    # ---------------------------------------------------------------
    def _restart_autosave_timer(self):
        try:
            if self._autosave_timer is not None:
                self._autosave_timer.stop()

            if self._log_file_path is None:
                self._autosave_status_lbl.setText("  \u26a0 choose a log file path first")
                return

            if not self._autosave_enabled_cb.isSelected():
                self._autosave_status_lbl.setText("  (auto-sync disabled)")
                return

            minutes = int(self._autosave_spinner.getValue())
            interval_ms = minutes * 60 * 1000

            def on_tick(event):
                imported = self._sync_from_history(silent=True)
                self._flush_all_to_disk()
                self._autosave_status_lbl.setText(
                    "  last auto-sync %s (+%d new)" % (time.strftime("%H:%M:%S"), imported))

            self._autosave_timer = Timer(interval_ms, on_tick)
            self._autosave_timer.setRepeats(True)
            self._autosave_timer.start()
            self._autosave_status_lbl.setText("  (auto-sync every %d min)" % minutes)
        except Exception as e:
            print("[TrafficLogger] Failed to (re)start autosave timer: %s" % str(e))

    # ---------------------------------------------------------------
    # Button actions
    # ---------------------------------------------------------------
    def _selected_entry(self):
        row = self._table.getSelectedRow()
        if row == -1:
            JOptionPane.showMessageDialog(self._traffic_panel, "Select a row first.")
            return None
        model_row = self._table.convertRowIndexToModel(row)
        idx = int(self._table_model.getValueAt(model_row, 0))
        return self.get_entry_by_index(idx)

    def _on_send_to_repeater(self, event):
        entry = self._selected_entry()
        if entry is None:
            return
        try:
            request_bytes = self._b64_to_bytes(entry["request_b64"])
            use_https = entry.get("protocol", "http") == "https"
            # If you left a comment on this entry, use it as the Repeater tab
            # title so you can recognize it at a glance. No comment -> blank title.
            comment = entry.get("comment", "") or ""
            title = comment[:50]  # keep tab titles readable
            self._callbacks.sendToRepeater(
                entry["host"], int(entry["port"]), use_https, request_bytes, title
            )
        except Exception as e:
            JOptionPane.showMessageDialog(self._traffic_panel, "Failed to send: %s" % str(e))

    def _on_sync_now(self, event):
        if not self._require_path("syncing"):
            return
        self._sync_from_history(silent=False)
        self._flush_all_to_disk()

    def _on_save_now(self, event):
        if not self._require_path("saving"):
            return
        self._flush_all_to_disk()
        self._autosave_status_lbl.setText("  manually saved: %s" % time.strftime("%H:%M:%S"))

    def _on_save_as(self, event):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("burp_traffic_export.jsonl"))
        result = chooser.showSaveDialog(self._traffic_panel)
        if result == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            try:
                f = FileWriter(path, False)
                bw = BufferedWriter(f)
                for entry in self._entries:
                    bw.write(json.dumps(self._serializable_entry(entry)))
                    bw.newLine()
                bw.close()
                f.close()
                JOptionPane.showMessageDialog(self._traffic_panel,
                                               "Saved %d entries to %s" % (len(self._entries), path))
            except Exception as e:
                JOptionPane.showMessageDialog(self._traffic_panel, "Save failed: %s" % str(e))

    def _on_load_from_file(self, event):
        chooser = JFileChooser()
        result = chooser.showOpenDialog(self._traffic_panel)
        if result == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            try:
                fr = FileReader(path)
                br = BufferedReader(fr)
                line = br.readLine()
                count = 0
                while line is not None:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        entry["index"] = len(self._entries)
                        entry.setdefault("highlight", "NONE")
                        entry.setdefault("comment", "")
                        self._entries.append(entry)
                        self._entries_by_index[entry["index"]] = entry
                        count += 1
                    line = br.readLine()
                br.close()
                fr.close()
                self._rebuild_table()
                JOptionPane.showMessageDialog(self._traffic_panel,
                                               "Loaded %d entries from %s" % (count, path))
            except Exception as e:
                JOptionPane.showMessageDialog(self._traffic_panel, "Load failed: %s" % str(e))

    def _on_clear(self, event):
        confirm = JOptionPane.showConfirmDialog(
            self._traffic_panel,
            "Clear the in-memory table? (Your log file on disk is kept unless you delete it manually.)",
            "Confirm", JOptionPane.YES_NO_OPTION)
        if confirm == JOptionPane.YES_OPTION:
            self._entries = []
            self._entries_by_index = {}
            self._seen_hashes = set()
            self._last_synced_history_count = 0
            self._table_model.setRowCount(0)
