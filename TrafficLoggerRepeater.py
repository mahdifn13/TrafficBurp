# -*- coding: utf-8 -*-
"""
Traffic Logger + Repeater Sender  (v4)
---------------------------------------
Burp Suite extension (Jython).

What's new in v4
  * Sync Now / auto-sync run in a BACKGROUND thread -> Burp's UI (EDT) no longer
    freezes with a big Proxy History. Table updates are posted back to the EDT.
  * Highlight / comment / delete changes are auto-saved to disk (debounced ~1.5s,
    written in a background thread). Also flushed when the extension is unloaded.
  * NEW "Repeater History" tab: every request you send from Repeater is recorded
    (request + response, response capped by size), searchable, with a request/
    response viewer, comments, and "Send to Repeater". Stored in
    <your log file>.repeater.jsonl (append-only, so it is cheap).
  * The chosen log file path is remembered inside the Burp project, and both logs
    are re-loaded automatically when you re-open the project.
  * Small fixes: index collision after Delete, search cache after comment edit,
    dedupe keys on Load, and a clearer prompt when picking an existing log file.

IMPORTANT limitation (Burp API): Burp does not expose the contents of its own
Repeater tabs/history to extensions. The only way is to record requests as they
are sent from Repeater (IHttpListener, TOOL_REPEATER). So Repeater history is
captured from the moment this extension is loaded; older Repeater activity cannot
be recovered. The API also does not tell us WHICH Repeater tab a request came
from, so use the Comment field to label what you were testing.

Requirements:
  - Jython standalone JAR configured under:
      Extender -> Options -> Python Environment -> Location of Jython standalone JAR

Install:
  Extender -> Extensions -> Add -> Extension type: Python -> select this file.

On first use:
  Click "Choose Log File..." in the Proxy Log tab and pick (or create) a file,
  e.g. traffic_log.jsonl.
"""

from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IExtensionStateListener
from burp import IMessageEditorController

from javax.swing import (JPanel, JTable, JScrollPane, JButton, JLabel,
                          JOptionPane, JFileChooser, JTabbedPane, JSplitPane,
                          JSpinner, SpinnerNumberModel, JCheckBox, JRadioButton,
                          ButtonGroup, JTextField, JPopupMenu, JMenuItem, JMenu,
                          Timer, JDialog, BoxLayout, SwingUtilities)
from javax.swing.border import EmptyBorder
from javax.swing.event import DocumentListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, FlowLayout, Color, GridLayout
from java.awt.event import MouseAdapter
from java.io import File, FileWriter, BufferedWriter, FileReader, BufferedReader
from java.lang import Runnable
from java.net import URL as JURL
from java.util import Base64

import json
import time
import os
import hashlib
import threading


COLUMN_NAMES = ["#", "Time", "Method", "Host", "URL", "Status", "Highlight", "Comment"]
REP_COLUMN_NAMES = ["#", "Time", "Method", "Host", "URL", "Status", "Resp len", "Comment"]

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

SETTING_LOG_PATH = "traffic_logger.log_file_path"
SAVE_DEBOUNCE_MS = 1500


class _Run(Runnable):
    """Wraps a Python callable as a java.lang.Runnable (for invokeLater)."""
    def __init__(self, fn):
        self._fn = fn

    def run(self):
        try:
            self._fn()
        except Exception as e:
            print("[TrafficLogger] EDT task failed: %s" % str(e))


def on_edt(fn):
    """Run fn on the Swing event dispatch thread (safe to call from any thread)."""
    SwingUtilities.invokeLater(_Run(fn))


def run_in_background(fn):
    t = threading.Thread(target=fn)
    t.setDaemon(True)
    t.start()
    return t


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


class BurpExtender(IBurpExtender, ITab, IHttpListener, IExtensionStateListener,
                   IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Traffic Logger + Repeater Sender")

        # --- shared state -------------------------------------------------
        self._lock = threading.RLock()          # guards entry lists / dicts
        self._flush_lock = threading.Lock()     # serialises main-log file writes
        self._rep_flush_lock = threading.Lock() # serialises repeater-log file writes

        # Proxy log
        self._entries = []
        self._entries_by_index = {}
        self._next_index = 0
        self._seen_hashes = set()
        self._last_synced_history_count = 0
        self._sync_running = False
        self._autosave_timer = None

        # Repeater history
        self._rep_entries = []
        self._rep_by_index = {}
        self._rep_next_index = 0
        self._rep_last_key = None
        self._rep_captured = 0
        self._rep_keep_disk = False       # True after Clear Table: file on disk still holds older entries
        self._rep_deleted_keys = set()    # entries the user explicitly deleted (must leave the file too)
        self._rep_saved = 0
        self._rep_last_error = ""
        self._rep_enabled = True
        self._rep_cap_kb = 256

        # Debounced disk save
        self._dirty_timer = None
        self._dirty_main = False
        self._dirty_rep = False

        # Message editor controller state (Repeater tab viewer)
        self._cur_service = None
        self._cur_req = None
        self._cur_resp = None

        self._log_file_path = None

        self._build_ui()

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        self._restore_saved_path()
        self._update_rep_status()

        print("[TrafficLogger] v4 loaded. Choose a log file path in the Proxy Log tab to begin.")

    # ---------------------------------------------------------------
    # UI construction
    # ---------------------------------------------------------------
    def _build_ui(self):
        self._build_settings_controls()
        self._build_traffic_tab()
        self._build_repeater_tab()
        self._root = JTabbedPane()
        self._root.addTab("Proxy Log", self._traffic_panel)
        self._root.addTab("Repeater History", self._rep_panel)

    def _build_traffic_tab(self):
        self._traffic_panel = JPanel(BorderLayout())

        top = JPanel()
        top.setLayout(GridLayout(2, 1))

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

        self._table_model = DefaultTableModel(COLUMN_NAMES, 0)
        self._table = JTable(self._table_model)
        self._table.setAutoCreateRowSorter(True)
        self._table.setToolTipText("Right-click a row for Highlight / Comment / Delete")
        renderer = HighlightRenderer(self)
        for col in range(len(COLUMN_NAMES)):
            self._table.getColumnModel().getColumn(col).setCellRenderer(renderer)
        self._table.addMouseListener(self._make_context_menu_listener())
        scroll = JScrollPane(self._table)

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

    def _build_repeater_tab(self):
        self._rep_panel = JPanel(BorderLayout())

        search_row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        search_row.add(JLabel("Search (payloads / params / headers / response):"))
        self._rep_search_field = JTextField(35)
        search_row.add(self._rep_search_field)
        search_row.add(JButton("Clear", actionPerformed=self._on_rep_clear_search))
        self._rep_match_lbl = JLabel("")
        search_row.add(self._rep_match_lbl)
        self._rep_status_lbl = JLabel("")
        search_row.add(self._rep_status_lbl)
        self._rep_search_field.getDocument().addDocumentListener(
            SearchDocumentListener(lambda: self._rebuild_rep_table()))

        self._rep_model = DefaultTableModel(REP_COLUMN_NAMES, 0)
        self._rep_table = JTable(self._rep_model)
        self._rep_table.setAutoCreateRowSorter(True)
        self._rep_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_rep_select(e))
        table_scroll = JScrollPane(self._rep_table)

        self._rep_req_editor = self._callbacks.createMessageEditor(self, False)
        self._rep_resp_editor = self._callbacks.createMessageEditor(self, False)
        viewers = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                             self._rep_req_editor.getComponent(),
                             self._rep_resp_editor.getComponent())
        viewers.setResizeWeight(0.5)
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, viewers)
        main_split.setResizeWeight(0.45)

        bottom = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        bottom.add(JButton("Load...", actionPerformed=self._on_rep_load))
        bottom.add(JButton("Send to Repeater", actionPerformed=self._on_rep_send))
        bottom.add(JButton("Add / Edit Comment...", actionPerformed=self._on_rep_comment))
        bottom.add(JButton("Delete Entry", actionPerformed=self._on_rep_delete))
        bottom.add(JButton("Clear Table", actionPerformed=self._on_rep_clear))

        self._rep_panel.add(search_row, BorderLayout.NORTH)
        self._rep_panel.add(main_split, BorderLayout.CENTER)
        self._rep_panel.add(bottom, BorderLayout.SOUTH)

    def _build_settings_controls(self):
        self._autosave_enabled_cb = JCheckBox("Enable auto-sync + auto-save every", True)
        self._autosave_spinner = JSpinner(SpinnerNumberModel(10, 1, 240, 1))
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

        # Repeater history settings (mirrored into plain attributes so the
        # HTTP-listener thread never touches Swing components)
        self._rep_enabled_cb = JCheckBox("Capture Repeater history", True)
        self._rep_enabled_cb.addActionListener(
            lambda e: setattr(self, "_rep_enabled", bool(self._rep_enabled_cb.isSelected())))
        self._rep_cap_spinner = JSpinner(SpinnerNumberModel(256, 0, 10240, 64))
        self._rep_cap_spinner.addChangeListener(
            lambda e: setattr(self, "_rep_cap_kb", int(self._rep_cap_spinner.getValue())))

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
        for rb, extra in ((self._scope_all_rb, None), (self._scope_burp_rb, None),
                          (self._scope_custom_rb, self._custom_domains_field)):
            row = JPanel(FlowLayout(FlowLayout.LEFT))
            row.add(rb)
            if extra is not None:
                row.add(extra)
            content.add(row)

        content.add(JLabel(" "))
        content.add(JLabel("Duplicates are always skipped automatically."))

        content.add(JLabel(" "))
        content.add(JLabel("Repeater history:"))
        rep_row1 = JPanel(FlowLayout(FlowLayout.LEFT))
        rep_row1.add(self._rep_enabled_cb)
        content.add(rep_row1)
        rep_row2 = JPanel(FlowLayout(FlowLayout.LEFT))
        rep_row2.add(JLabel("Store response up to"))
        rep_row2.add(self._rep_cap_spinner)
        rep_row2.add(JLabel("KB per request (0 = don't store responses)"))
        content.add(rep_row2)

        close_row = JPanel(FlowLayout(FlowLayout.RIGHT))
        close_row.add(JButton("Close", actionPerformed=lambda e: dialog.dispose()))

        dialog.add(content, BorderLayout.CENTER)
        dialog.add(close_row, BorderLayout.SOUTH)
        dialog.pack()
        dialog.setLocationRelativeTo(owner_window)
        dialog.setVisible(True)

    def getTabCaption(self):
        return "Traffic Logger"

    def getUiComponent(self):
        return self._root

    def _set_status(self, text):
        on_edt(lambda: self._autosave_status_lbl.setText(text))

    # ---------------------------------------------------------------
    # IMessageEditorController (used by the Repeater History viewers)
    # ---------------------------------------------------------------
    def getHttpService(self):
        return self._cur_service

    def getRequest(self):
        return self._cur_req

    def getResponse(self):
        return self._cur_resp

    # ---------------------------------------------------------------
    # Log file path selection
    # ---------------------------------------------------------------
    def _on_choose_log_path(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Choose or create a log file")
        chooser.setSelectedFile(File("burp_traffic_log.jsonl"))
        result = chooser.showDialog(self._traffic_panel, "Select")
        if result != JFileChooser.APPROVE_OPTION:
            return

        path = chooser.getSelectedFile().getAbsolutePath()
        load_main = False
        # Repeater history is NEVER overwritten or skipped: if its file exists it is
        # always merged in automatically (no prompt that could leave the path unset).
        load_rep = os.path.exists(self._repeater_path(path))

        if os.path.exists(path):
            answer = JOptionPane.showConfirmDialog(
                self._traffic_panel,
                "This log file already has data.\n\n"
                "YES    = load the existing entries from it\n"
                "NO     = start fresh (this log file will be OVERWRITTEN on next save;\n"
                "         Repeater history is always kept)\n"
                "CANCEL = keep the current log file",
                "Existing log file", JOptionPane.YES_NO_CANCEL_OPTION)
            if answer == JOptionPane.CANCEL_OPTION or answer == JOptionPane.CLOSED_OPTION:
                return
            load_main = (answer == JOptionPane.YES_OPTION)

        self._log_file_path = path
        self._path_field.setText(path)
        try:
            self._callbacks.saveExtensionSetting(SETTING_LOG_PATH, path)
        except Exception:
            pass

        with self._lock:
            self._entries = []
            self._entries_by_index = {}
            self._next_index = 0
            self._seen_hashes = set()
        self._table_model.setRowCount(0)
        self._last_synced_history_count = 0

        def work():
            if load_main:
                self._load_from_disk(path)
            if load_rep:
                self._load_repeater_from_disk(path)
            # save Repeater captures made before a path existed (never writes an empty file)
            if self._rep_entries:
                self._flush_repeater_all()
            self._update_rep_status()
            on_edt(lambda: JOptionPane.showMessageDialog(
                self._traffic_panel, "Log file set to:\n%s" % path))

        self._restart_autosave_timer()
        run_in_background(work)

    def _restore_saved_path(self):
        """On extension load (e.g. re-opening a Burp project) re-use the last log file."""
        try:
            saved = self._callbacks.loadExtensionSetting(SETTING_LOG_PATH)
        except Exception:
            saved = None
        if not saved or not (os.path.exists(saved) or os.path.exists(self._repeater_path(saved))):
            return
        self._log_file_path = saved
        self._path_field.setText(saved)
        self._restart_autosave_timer()

        def work():
            self._set_status("  loading saved logs...")
            self._load_from_disk(saved)
            self._load_repeater_from_disk(saved)
            self._set_status("  restored log from last session")
        run_in_background(work)

    def _require_path(self, action_description):
        if self._log_file_path is None:
            JOptionPane.showMessageDialog(
                self._traffic_panel,
                "Choose a log file path first (button at the top) before %s." % action_description)
            return False
        return True

    def _repeater_path(self, base=None):
        base = base or self._log_file_path
        if base is None:
            return None
        return base + ".repeater.jsonl"

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

        menu.add(JMenuItem("Send to Repeater", actionPerformed=self._on_send_to_repeater))
        menu.addSeparator()

        highlight_menu = JMenu("Highlight")
        for color_name in ["NONE", "RED", "ORANGE", "YELLOW", "GREEN", "CYAN", "PINK", "GRAY"]:
            item = JMenuItem(color_name)
            item.addActionListener(self._make_highlight_action(color_name))
            highlight_menu.add(item)
        menu.add(highlight_menu)

        menu.add(JMenuItem("Add / Edit Comment...", actionPerformed=self._on_edit_comment))
        menu.addSeparator()
        menu.add(JMenuItem("Delete Entry", actionPerformed=self._on_delete_entry))

        menu.show(component, x, y)

    def _make_highlight_action(self, color_name):
        def action(event):
            entry = self._selected_entry()
            if entry is None:
                return
            entry["highlight"] = color_name
            self._table.repaint()          # no full rebuild -> selection is kept
            self._mark_dirty(main=True)    # persist to disk (debounced, background)
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
            entry.pop("_decoded_lower", None)   # search cache includes the comment
            self._rebuild_table()
            self._mark_dirty(main=True)

    def _on_delete_entry(self, event):
        entry = self._selected_entry()
        if entry is None:
            return
        confirm = JOptionPane.showConfirmDialog(
            self._traffic_panel, "Delete this entry from the table?", "Confirm",
            JOptionPane.YES_NO_OPTION)
        if confirm == JOptionPane.YES_OPTION:
            with self._lock:
                if entry in self._entries:
                    self._entries.remove(entry)
                self._entries_by_index.pop(entry["index"], None)
            self._rebuild_table()
            self._mark_dirty(main=True)

    def _rebuild_table(self):
        query = ""
        try:
            query = self._search_field.getText().strip().lower()
        except Exception:
            pass

        with self._lock:
            entries = list(self._entries)

        self._table_model.setRowCount(0)
        shown = 0
        for entry in entries:
            if query and query not in self._get_searchable_text(entry):
                continue
            shown += 1
            self._table_model.addRow([entry["index"], entry.get("time", ""),
                                       entry.get("method", ""), entry.get("host", ""),
                                       entry.get("url", ""), entry.get("status", ""),
                                       entry.get("highlight", "NONE"), entry.get("comment", "")])

        try:
            if query:
                self._search_match_lbl.setText("  %d / %d match" % (shown, len(entries)))
            else:
                self._search_match_lbl.setText("")
        except Exception:
            pass

    def _request_rebuild(self):
        on_edt(self._rebuild_table)

    def _get_searchable_text(self, entry):
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
    # Pull traffic from Burp's Proxy History -- in a BACKGROUND thread
    # ---------------------------------------------------------------
    def _snapshot_scope(self):
        """Read the Swing scope controls on the EDT; the worker uses this plain dict."""
        if self._scope_burp_rb.isSelected():
            mode = "burp"
        elif self._scope_custom_rb.isSelected():
            mode = "custom"
        else:
            mode = "all"
        raw = self._custom_domains_field.getText()
        domains = [d.strip().lower().lstrip("*.") for d in raw.split(",") if d.strip()]
        return {"mode": mode, "domains": domains}

    def _start_sync(self, silent):
        """Must be called on the EDT. Returns False if a sync is already running."""
        if self._sync_running:
            if not silent:
                JOptionPane.showMessageDialog(self._traffic_panel,
                                              "A sync is already running, please wait.")
            return False
        self._sync_running = True
        scope = self._snapshot_scope()
        run_in_background(lambda: self._sync_worker(silent, scope))
        return True

    def _sync_worker(self, silent, scope):
        imported = 0
        scanned = 0
        skipped = 0
        error = None
        try:
            self._set_status("  syncing from Proxy History...")
            history = self._callbacks.getProxyHistory()
            total = len(history)

            start_index = self._last_synced_history_count
            if start_index > total:
                start_index = 0
            skipped = start_index
            scanned = total - start_index

            for n, i in enumerate(range(start_index, total)):
                if self._process_history_item(history[i], scope):
                    imported += 1
                if n and n % 500 == 0:
                    self._set_status("  syncing... %d / %d" % (n, scanned))

            self._last_synced_history_count = total

            if imported > 0:
                self._request_rebuild()

            self._flush_all_to_disk()
            self._set_status("  last auto-sync %s (+%d new)" % (time.strftime("%H:%M:%S"), imported))
        except Exception as e:
            error = str(e)
            print("[TrafficLogger] Sync failed: %s" % error)
            self._set_status("  sync failed: %s" % error)
        finally:
            self._sync_running = False

        if not silent:
            if error is not None:
                msg = "Sync failed: %s" % error
            else:
                msg = ("Pulled %d new item(s) from Proxy History (scanned %d new, skipped %d already-seen)."
                       % (imported, scanned, skipped))
            on_edt(lambda: JOptionPane.showMessageDialog(self._traffic_panel, msg))

    def _process_history_item(self, messageInfo, scope):
        """Runs on the worker thread. Returns True if a new entry was added."""
        http_service = messageInfo.getHttpService()
        host = http_service.getHost()
        port = http_service.getPort()
        protocol = http_service.getProtocol()

        request_bytes = messageInfo.getRequest()
        response_bytes = messageInfo.getResponse()

        request_info = self._helpers.analyzeRequest(messageInfo)
        method = request_info.getMethod()
        url = str(request_info.getUrl())

        if not self._passes_scope_filter(url, host, scope):
            return False

        dedupe_key = self._make_dedupe_key(method, url, request_bytes)

        status = ""
        if response_bytes is not None:
            response_info = self._helpers.analyzeResponse(response_bytes)
            status = str(response_info.getStatusCode())

        request_b64 = self._bytes_to_b64(request_bytes)

        with self._lock:
            if dedupe_key in self._seen_hashes:
                return False
            self._seen_hashes.add(dedupe_key)
            entry = {
                "index": self._next_index,
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "method": method,
                "host": host,
                "port": port,
                "protocol": protocol,
                "url": url,
                "status": status,
                "request_b64": request_b64,
                "highlight": "NONE",
                "comment": "",
                "dedupe_key": dedupe_key,
            }
            self._next_index += 1
            self._entries.append(entry)
            self._entries_by_index[entry["index"]] = entry
        return True

    def get_entry_by_index(self, idx):
        return self._entries_by_index.get(idx)

    # ---------------------------------------------------------------
    # Scope filter + dedupe helpers
    # ---------------------------------------------------------------
    def _passes_scope_filter(self, url, host, scope):
        mode = scope["mode"]
        if mode == "all":
            return True
        if mode == "burp":
            try:
                return self._callbacks.isInScope(JURL(url))
            except Exception:
                return False
        host_lower = host.lower()
        for d in scope["domains"]:
            if host_lower == d or host_lower.endswith("." + d):
                return True
        return False

    def _make_dedupe_key(self, method, url, request_bytes):
        # NOTE: kept identical to v3 so dedupe keys already stored in old log files still match.
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
    # Persistence -- proxy log
    # ---------------------------------------------------------------
    def _serializable_entry(self, entry):
        return dict((k, v) for k, v in entry.items() if not k.startswith("_"))

    def _flush_all_to_disk(self):
        """Thread-safe. Call from background threads (or on unload)."""
        path = self._log_file_path
        if path is None:
            return
        with self._flush_lock:
            try:
                with self._lock:
                    snapshot = [self._serializable_entry(e) for e in self._entries]
                tmp_path = path + ".tmp"
                f = open(tmp_path, "w")
                try:
                    for entry in snapshot:
                        f.write(json.dumps(entry))
                        f.write("\n")
                finally:
                    f.close()
                if os.path.exists(path):
                    os.remove(path)
                os.rename(tmp_path, path)
            except Exception as e:
                print("[TrafficLogger] Failed to flush log: %s" % str(e))

    def _add_loaded_entry(self, entry):
        """Insert an entry read from disk (caller holds self._lock)."""
        entry["index"] = self._next_index
        self._next_index += 1
        entry.setdefault("highlight", "NONE")
        entry.setdefault("comment", "")
        self._entries.append(entry)
        self._entries_by_index[entry["index"]] = entry
        if "dedupe_key" in entry:
            self._seen_hashes.add(entry["dedupe_key"])

    def _read_jsonl(self, path):
        rows = []
        f = open(path, "r")
        try:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
        finally:
            f.close()
        return rows

    def _load_from_disk(self, path):
        """Safe to call from a background thread."""
        if not os.path.exists(path):
            return
        try:
            rows = self._read_jsonl(path)
            with self._lock:
                for entry in rows:
                    self._add_loaded_entry(entry)
                total = len(self._entries)
            self._request_rebuild()
            print("[TrafficLogger] Loaded %d entries from %s" % (total, path))
        except Exception as e:
            print("[TrafficLogger] Failed to load log: %s" % str(e))

    # ---------------------------------------------------------------
    # Debounced background saving (highlight / comment / delete)
    # ---------------------------------------------------------------
    def _mark_dirty(self, main=False, rep=False):
        """Call on the EDT. Coalesces rapid edits into one background write."""
        if main:
            self._dirty_main = True
        if rep:
            self._dirty_rep = True
        if self._log_file_path is None:
            return  # nothing is saved until the user picks a log file
        if self._dirty_timer is None:
            self._dirty_timer = Timer(SAVE_DEBOUNCE_MS, self._on_dirty_fire)
            self._dirty_timer.setRepeats(False)
        self._dirty_timer.restart()

    def _on_dirty_fire(self, event):
        main, rep = self._dirty_main, self._dirty_rep
        self._dirty_main = False
        self._dirty_rep = False

        def work():
            if main:
                self._flush_all_to_disk()
            if rep:
                self._flush_repeater_all()
        run_in_background(work)

    # ---------------------------------------------------------------
    # Auto-sync + auto-save timer (fires on EDT, but only STARTS a worker)
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
                self._start_sync(silent=True)

            self._autosave_timer = Timer(interval_ms, on_tick)
            self._autosave_timer.setRepeats(True)
            self._autosave_timer.start()
            self._autosave_status_lbl.setText("  (auto-sync every %d min)" % minutes)
        except Exception as e:
            print("[TrafficLogger] Failed to (re)start autosave timer: %s" % str(e))

    # ---------------------------------------------------------------
    # Proxy-log button actions
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
            comment = entry.get("comment", "") or ""
            title = comment[:50]
            self._callbacks.sendToRepeater(
                entry["host"], int(entry["port"]), use_https, request_bytes, title
            )
        except Exception as e:
            JOptionPane.showMessageDialog(self._traffic_panel, "Failed to send: %s" % str(e))

    def _on_sync_now(self, event):
        if not self._require_path("syncing"):
            return
        self._start_sync(silent=False)   # returns immediately; work happens in background

    def _on_save_now(self, event):
        if not self._require_path("saving"):
            return

        def work():
            self._flush_all_to_disk()
            self._flush_repeater_all()
            self._set_status("  manually saved: %s" % time.strftime("%H:%M:%S"))
        run_in_background(work)

    def _on_save_as(self, event):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("burp_traffic_export.jsonl"))
        result = chooser.showSaveDialog(self._traffic_panel)
        if result == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            try:
                with self._lock:
                    snapshot = [self._serializable_entry(e) for e in self._entries]
                f = FileWriter(path, False)
                bw = BufferedWriter(f)
                for entry in snapshot:
                    bw.write(json.dumps(entry))
                    bw.newLine()
                bw.close()
                f.close()
                JOptionPane.showMessageDialog(self._traffic_panel,
                                               "Saved %d entries to %s" % (len(snapshot), path))
            except Exception as e:
                JOptionPane.showMessageDialog(self._traffic_panel, "Save failed: %s" % str(e))

    def _on_load_from_file(self, event):
        chooser = JFileChooser()
        result = chooser.showOpenDialog(self._traffic_panel)
        if result == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            try:
                rows = self._read_jsonl(path)
                with self._lock:
                    for entry in rows:
                        self._add_loaded_entry(entry)   # also registers dedupe keys
                self._rebuild_table()
                self._mark_dirty(main=True)
                JOptionPane.showMessageDialog(self._traffic_panel,
                                               "Loaded %d entries from %s" % (len(rows), path))
            except Exception as e:
                JOptionPane.showMessageDialog(self._traffic_panel, "Load failed: %s" % str(e))

    def _on_clear(self, event):
        confirm = JOptionPane.showConfirmDialog(
            self._traffic_panel,
            "Clear the in-memory table? (Your log file on disk is kept unless you delete it manually.)",
            "Confirm", JOptionPane.YES_NO_OPTION)
        if confirm == JOptionPane.YES_OPTION:
            with self._lock:
                self._entries = []
                self._entries_by_index = {}
                self._next_index = 0
                self._seen_hashes = set()
            self._last_synced_history_count = 0
            self._table_model.setRowCount(0)

    # ---------------------------------------------------------------
    # REPEATER HISTORY
    # ---------------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """IHttpListener. Called by Burp for every HTTP message of every tool.
        We only care about completed (response) messages coming from Repeater."""
        if messageIsRequest:
            return
        if toolFlag != self._callbacks.TOOL_REPEATER:
            return
        if not self._rep_enabled:
            return
        try:
            self._capture_repeater(messageInfo)
        except Exception as e:
            self._rep_last_error = "capture: %s" % str(e)
            print("[TrafficLogger] Repeater capture failed: %s" % str(e))
            self._update_rep_status()

    def _capture_repeater(self, messageInfo):
        service = messageInfo.getHttpService()
        host = service.getHost()
        port = service.getPort()
        protocol = service.getProtocol()

        request_bytes = messageInfo.getRequest()
        response_bytes = messageInfo.getResponse()
        if request_bytes is None:
            return

        # Skip an immediate exact re-send of the same request (e.g. double-click on Send)
        req_text = self._helpers.bytesToString(request_bytes)
        h = hashlib.sha1()
        h.update(("%s:%s:" % (host, port)).encode("utf-8"))
        h.update(req_text.encode("utf-8", "replace"))
        key = h.hexdigest()

        info = self._helpers.analyzeRequest(messageInfo)
        method = info.getMethod()
        url = str(info.getUrl())

        status = ""
        resp_len = 0
        resp_b64 = ""
        truncated = False
        if response_bytes is not None:
            try:
                status = str(self._helpers.analyzeResponse(response_bytes).getStatusCode())
            except Exception:
                pass
            resp_len = len(response_bytes)
            cap = int(self._rep_cap_kb) * 1024
            if cap > 0:
                if resp_len > cap:
                    resp_b64 = self._bytes_to_b64(response_bytes[:cap])
                    truncated = True
                else:
                    resp_b64 = self._bytes_to_b64(response_bytes)

        with self._lock:
            if key == self._rep_last_key and self._rep_entries \
                    and self._rep_entries[-1].get("status", "") == status:
                return
            self._rep_last_key = key
            entry = {
                "index": self._rep_next_index,
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "method": method,
                "host": host,
                "port": port,
                "protocol": protocol,
                "url": url,
                "status": status,
                "resp_len": resp_len,
                "resp_truncated": truncated,
                "request_b64": self._bytes_to_b64(request_bytes),
                "response_b64": resp_b64,
                "comment": "",
            }
            self._rep_next_index += 1
            self._rep_entries.append(entry)
            self._rep_by_index[entry["index"]] = entry

        self._rep_captured += 1
        self._append_repeater_to_disk(entry)
        on_edt(self._rebuild_rep_table)
        self._update_rep_status()

    def _append_repeater_to_disk(self, entry):
        path = self._repeater_path()
        if path is None:
            return  # no log file chosen yet; saved when the user picks one
        with self._rep_flush_lock:
            try:
                f = open(path, "a")
                try:
                    f.write(json.dumps(self._serializable_entry(entry)))
                    f.write("\n")
                finally:
                    f.close()
                self._rep_saved += 1
            except Exception as e:
                self._rep_last_error = "write: %s" % str(e)
                print("[TrafficLogger] Failed to append repeater log: %s" % str(e))

    def _flush_repeater_all(self):
        """Rewrite the whole repeater file (used after comment/delete/clear or first path choice)."""
        path = self._repeater_path()
        if path is None:
            return
        with self._rep_flush_lock:
            try:
                with self._lock:
                    snapshot = [self._serializable_entry(e) for e in self._rep_entries]
                    keep_disk = self._rep_keep_disk
                    deleted = set(self._rep_deleted_keys)
                if keep_disk and os.path.exists(path):
                    # Table was cleared earlier: keep older entries that only live on disk
                    # (except ones explicitly deleted, and ones already in memory).
                    in_mem = set((e.get("time"), e.get("request_b64")) for e in snapshot)
                    old_rows = []
                    for row in self._read_jsonl(path):
                        k = (row.get("time"), row.get("request_b64"))
                        if k in in_mem or k in deleted:
                            continue
                        old_rows.append(row)
                    snapshot = old_rows + snapshot
                tmp_path = path + ".tmp"
                f = open(tmp_path, "w")
                try:
                    for entry in snapshot:
                        f.write(json.dumps(entry))
                        f.write("\n")
                finally:
                    f.close()
                if os.path.exists(path):
                    os.remove(path)
                os.rename(tmp_path, path)
            except Exception as e:
                self._rep_last_error = "flush: %s" % str(e)
                print("[TrafficLogger] Failed to flush repeater log: %s" % str(e))

    def _load_repeater_from_disk(self, base_path):
        path = self._repeater_path(base_path)
        if path is None or not os.path.exists(path):
            return
        try:
            rows = self._read_jsonl(path)
            with self._lock:
                existing = set((e.get("time"), e.get("request_b64")) for e in self._rep_entries)
                for entry in rows:
                    k = (entry.get("time"), entry.get("request_b64"))
                    if k in existing:
                        continue
                    existing.add(k)
                    entry["index"] = self._rep_next_index
                    self._rep_next_index += 1
                    entry.setdefault("comment", "")
                    self._rep_entries.append(entry)
                    self._rep_by_index[entry["index"]] = entry
                total = len(self._rep_entries)
            on_edt(self._rebuild_rep_table)
            print("[TrafficLogger] Loaded %d Repeater entries from %s" % (total, path))
        except Exception as e:
            print("[TrafficLogger] Failed to load repeater log: %s" % str(e))

    def _get_rep_searchable_text(self, entry):
        cached = entry.get("_decoded_lower")
        if cached is not None:
            return cached
        parts = []
        try:
            parts.append(self._helpers.bytesToString(self._b64_to_bytes(entry.get("request_b64", ""))))
        except Exception:
            parts.append(entry.get("url", ""))
        try:
            if entry.get("response_b64"):
                parts.append(self._helpers.bytesToString(self._b64_to_bytes(entry["response_b64"])))
        except Exception:
            pass
        parts.append(entry.get("comment", ""))
        text_lower = "\n".join(parts).lower()
        entry["_decoded_lower"] = text_lower
        return text_lower

    def _rebuild_rep_table(self):
        query = ""
        try:
            query = self._rep_search_field.getText().strip().lower()
        except Exception:
            pass
        with self._lock:
            entries = list(self._rep_entries)

        self._rep_model.setRowCount(0)
        shown = 0
        for entry in entries:
            if query and query not in self._get_rep_searchable_text(entry):
                continue
            shown += 1
            self._rep_model.addRow([entry["index"], entry.get("time", ""),
                                     entry.get("method", ""), entry.get("host", ""),
                                     entry.get("url", ""), entry.get("status", ""),
                                     entry.get("resp_len", ""), entry.get("comment", "")])
        try:
            if query:
                self._rep_match_lbl.setText("  %d / %d match" % (shown, len(entries)))
            else:
                self._rep_match_lbl.setText("  %d entries" % len(entries))
        except Exception:
            pass

    def _update_rep_status(self):
        def apply():
            if self._log_file_path is None:
                where = "NOT SAVING to disk - choose a log file in the Proxy Log tab"
            else:
                where = "saving to %s" % self._repeater_path()
            txt = "   captured: %d | written: %d | %s" % (self._rep_captured, self._rep_saved, where)
            if self._rep_last_error:
                txt += " | last error: %s" % self._rep_last_error
            self._rep_status_lbl.setText(txt)
        on_edt(apply)

    def _on_rep_load(self, event):
        """Load any *.repeater.jsonl file into the Repeater History tab (merges, skips duplicates)."""
        chooser = JFileChooser()
        chooser.setDialogTitle("Load Repeater history file (e.g. test.repeater.jsonl)")
        if chooser.showOpenDialog(self._rep_panel) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()

        def work():
            added = 0
            total = 0
            err = None
            try:
                rows = self._read_jsonl(path)
                total = len(rows)
                with self._lock:
                    existing = set((e.get("time"), e.get("request_b64")) for e in self._rep_entries)
                    for entry in rows:
                        k = (entry.get("time"), entry.get("request_b64"))
                        if k in existing:
                            continue
                        existing.add(k)
                        entry["index"] = self._rep_next_index
                        self._rep_next_index += 1
                        entry.setdefault("comment", "")
                        self._rep_entries.append(entry)
                        self._rep_by_index[entry["index"]] = entry
                        added += 1
                on_edt(self._rebuild_rep_table)
                if added:
                    on_edt(lambda: self._mark_dirty(rep=True))  # also save into the current log's repeater file
            except Exception as ex:
                err = str(ex)
            if err is not None:
                msg = "Load failed: %s" % err
            else:
                msg = "Loaded %d new entries (%d in file, %d already present)." % (added, total, total - added)
            on_edt(lambda: JOptionPane.showMessageDialog(self._rep_panel, msg))
        run_in_background(work)

    def _on_rep_clear_search(self, event):
        self._rep_search_field.setText("")
        self._rebuild_rep_table()

    def _selected_rep_entry(self, warn=True):
        row = self._rep_table.getSelectedRow()
        if row == -1:
            if warn:
                JOptionPane.showMessageDialog(self._rep_panel, "Select a row first.")
            return None
        model_row = self._rep_table.convertRowIndexToModel(row)
        idx = int(self._rep_model.getValueAt(model_row, 0))
        return self._rep_by_index.get(idx)

    def _on_rep_select(self, event):
        try:
            if event is not None and event.getValueIsAdjusting():
                return
            entry = self._selected_rep_entry(warn=False)
            if entry is None:
                return
            req = self._b64_to_bytes(entry["request_b64"])
            resp = None
            if entry.get("response_b64"):
                resp = self._b64_to_bytes(entry["response_b64"])
            self._cur_service = self._helpers.buildHttpService(
                entry["host"], int(entry["port"]), entry.get("protocol", "http"))
            self._cur_req = req
            self._cur_resp = resp
            self._rep_req_editor.setMessage(req, True)
            if resp is not None:
                self._rep_resp_editor.setMessage(resp, False)
            else:
                note = "(no response stored)"
                if int(entry.get("resp_len", 0) or 0) > 0:
                    note = "(response not stored - cap set to 0 KB)"
                self._rep_resp_editor.setMessage(self._helpers.stringToBytes(note), False)
        except Exception as e:
            print("[TrafficLogger] Failed to show Repeater entry: %s" % str(e))

    def _on_rep_send(self, event):
        entry = self._selected_rep_entry()
        if entry is None:
            return
        try:
            use_https = entry.get("protocol", "http") == "https"
            title = (entry.get("comment", "") or "")[:50]
            self._callbacks.sendToRepeater(
                entry["host"], int(entry["port"]), use_https,
                self._b64_to_bytes(entry["request_b64"]), title)
        except Exception as e:
            JOptionPane.showMessageDialog(self._rep_panel, "Failed to send: %s" % str(e))

    def _on_rep_comment(self, event):
        entry = self._selected_rep_entry()
        if entry is None:
            return
        new_comment = JOptionPane.showInputDialog(
            self._rep_panel,
            "Comment for %s %s:" % (entry.get("method", ""), entry.get("url", "")),
            entry.get("comment", ""))
        if new_comment is not None:
            entry["comment"] = new_comment
            entry.pop("_decoded_lower", None)
            self._rebuild_rep_table()
            self._mark_dirty(rep=True)

    def _on_rep_delete(self, event):
        entry = self._selected_rep_entry()
        if entry is None:
            return
        confirm = JOptionPane.showConfirmDialog(
            self._rep_panel, "Delete this Repeater history entry?", "Confirm",
            JOptionPane.YES_NO_OPTION)
        if confirm == JOptionPane.YES_OPTION:
            with self._lock:
                if entry in self._rep_entries:
                    self._rep_entries.remove(entry)
                self._rep_by_index.pop(entry["index"], None)
                self._rep_deleted_keys.add((entry.get("time"), entry.get("request_b64")))
            self._rebuild_rep_table()
            self._mark_dirty(rep=True)

    def _on_rep_clear(self, event):
        confirm = JOptionPane.showConfirmDialog(
            self._rep_panel,
            "Clear the Repeater History table? (The .repeater.jsonl file on disk is kept;\n"
            "use Load... to bring entries back.)",
            "Confirm", JOptionPane.YES_NO_OPTION)
        if confirm == JOptionPane.YES_OPTION:
            with self._lock:
                self._rep_entries = []
                self._rep_by_index = {}
                self._rep_next_index = 0
                self._rep_last_key = None
                self._rep_keep_disk = True
            self._rebuild_rep_table()

    # ---------------------------------------------------------------
    # IExtensionStateListener
    # ---------------------------------------------------------------
    def extensionUnloaded(self):
        """Burp is closing / extension unloaded: stop timers and flush synchronously."""
        try:
            if self._autosave_timer is not None:
                self._autosave_timer.stop()
            if self._dirty_timer is not None:
                self._dirty_timer.stop()
            self._flush_all_to_disk()
            self._flush_repeater_all()
        except Exception as e:
            print("[TrafficLogger] Error during unload: %s" % str(e))
