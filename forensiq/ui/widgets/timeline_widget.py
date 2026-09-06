"""
forensiq/ui/widgets/timeline_widget.py
--------------------------------------
Interactive forensic timeline scrubber widget.

Displays:
- Visual time axis with tick marks and timecodes.
- Color-coded event markers (METADATA, AI_PRELIMINARY, BOOKMARKS, ANOMALIES).
- Movable scrubber playhead with interactive click-and-drag navigation.
- Tooltips displaying event descriptions and timestamps on hover.

Phase 5: Fully implemented.
"""

from typing import Optional

from PySide6.QtCore import QPoint, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QMouseEvent, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import QToolTip, QWidget

from forensiq.constants import TimelineEventType
from forensiq.models.timeline import TimelineEvent
from forensiq.utils.utc_utils import to_iso8601


class TimelineWidget(QWidget):
    """
    Visual timeline bar showing events and current scrubber position.
    """

    position_changed = Signal(float)  # Emits current offset in seconds
    event_selected = Signal(str)      # Emits event_id

    # Color coding for event types
    _TYPE_COLORS = {
        TimelineEventType.METADATA.value: QColor("#fbbf24"),         # Yellow / Amber
        TimelineEventType.AI_PRELIMINARY.value: QColor("#c084fc"),   # Purple
        TimelineEventType.ANALYST_BOOKMARK.value: QColor("#38bdf8"), # Sky Blue
        TimelineEventType.MANUAL_ENTRY.value: QColor("#34d399"),     # Green
        "GAP": QColor("#f87171"),                                    # Red
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(68)
        self.setMinimumWidth(400)
        self.setMouseTracking(True)

        self._events: list[TimelineEvent] = []
        self._duration_seconds: float = 60.0
        self._current_position: float = 0.0
        self._is_dragging: bool = False
        self._marker_rects: list[tuple[QRectF, TimelineEvent]] = []

    def set_duration(self, duration_seconds: float) -> None:
        """Set the total timeline duration in seconds."""
        self._duration_seconds = max(1.0, float(duration_seconds or 60.0))
        self.update()

    def set_events(self, events: list[TimelineEvent], duration_seconds: Optional[float] = None) -> None:
        """Load timeline events into the widget."""
        self._events = list(events)
        if duration_seconds and duration_seconds > 0:
            self._duration_seconds = duration_seconds
        elif self._events:
            # Calculate max offset
            max_offset = max(
                (e.offset_seconds or 0.0 for e in self._events),
                default=60.0,
            )
            self._duration_seconds = max(60.0, max_offset * 1.1)

        self.update()

    def set_current_position(self, seconds: float) -> None:
        """Update current scrubber position in seconds."""
        self._current_position = max(0.0, min(self._duration_seconds, seconds))
        self.update()

    # ─────────────────────────────────────────────────────────────────────────
    # Painting
    # ─────────────────────────────────────────────────────────────────────────

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        margin_x = 24
        track_y = 32
        track_h = 10
        track_w = w - (margin_x * 2)

        # 1. Background
        painter.fillRect(0, 0, w, h, QColor("#0a1118"))

        # Border
        painter.setPen(QPen(QColor("#1e3a5f"), 1))
        painter.drawRoundedRect(0, 0, w - 1, h - 1, 4, 4)

        # 2. Time axis ticks & labels
        font = QFont("Segoe UI", 8)
        painter.setFont(font)
        painter.setPen(QColor("#64748b"))

        num_ticks = 6
        for i in range(num_ticks + 1):
            ratio = i / num_ticks
            x = margin_x + (ratio * track_w)
            t_sec = ratio * self._duration_seconds
            mins = int(t_sec // 60)
            secs = int(t_sec % 60)
            time_str = f"{mins:02d}:{secs:02d}"

            # Tick mark
            painter.drawLine(int(x), track_y - 8, int(x), track_y - 2)
            # Label
            painter.drawText(int(x - 18), track_y - 12, 36, 12, Qt.AlignCenter, time_str)

        # 3. Main timeline track
        painter.setBrush(QBrush(QColor("#121f2d")))
        painter.setPen(QPen(QColor("#2d4a6a"), 1))
        painter.drawRoundedRect(margin_x, track_y, track_w, track_h, 4, 4)

        # 4. Progress fill up to current position
        if self._duration_seconds > 0 and self._current_position > 0:
            fill_ratio = min(1.0, self._current_position / self._duration_seconds)
            fill_w = fill_ratio * track_w
            painter.setBrush(QBrush(QColor("#0369a1")))
            painter.setPen(Qt.NoPen)
            painter.drawRoundedRect(margin_x, track_y, fill_w, track_h, 3, 3)

        # 5. Event markers
        self._marker_rects.clear()
        for ev in self._events:
            offset = ev.offset_seconds or 0.0
            ratio = min(1.0, max(0.0, offset / self._duration_seconds))
            marker_x = margin_x + (ratio * track_w)
            color = self._TYPE_COLORS.get(ev.event_type, QColor("#38bdf8"))

            painter.setBrush(QBrush(color))
            painter.setPen(QPen(QColor("#0a1118"), 1))

            # Diamond marker below track
            diamond = QPolygonF([
                QPoint(int(marker_x), track_y + track_h + 3),
                QPoint(int(marker_x + 5), track_y + track_h + 9),
                QPoint(int(marker_x), track_y + track_h + 15),
                QPoint(int(marker_x - 5), track_y + track_h + 9),
            ])
            painter.drawPolygon(diamond)

            # Store hit-test bounding box
            hit_rect = QRectF(marker_x - 6, track_y + track_h + 2, 12, 14)
            self._marker_rects.append((hit_rect, ev))

        # 6. Scrubber playhead (cyan needle)
        scrubber_ratio = min(1.0, max(0.0, self._current_position / self._duration_seconds))
        scrubber_x = margin_x + (scrubber_ratio * track_w)

        painter.setPen(QPen(QColor("#38bdf8"), 2))
        painter.drawLine(int(scrubber_x), track_y - 4, int(scrubber_x), track_y + track_h + 4)

        # Scrubber thumb
        painter.setBrush(QBrush(QColor("#38bdf8")))
        painter.setPen(QPen(QColor("#0a1118"), 1))
        painter.drawEllipse(QPoint(int(scrubber_x), track_y + (track_h // 2)), 5, 5)

    # ─────────────────────────────────────────────────────────────────────────
    # Mouse Interactions
    # ─────────────────────────────────────────────────────────────────────────

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            # Check if clicked on a marker
            pos = event.position()
            for rect, ev in self._marker_rects:
                if rect.contains(pos):
                    self.event_selected.emit(ev.id)
                    return

            self._is_dragging = True
            self._update_position_from_mouse(event.position().x())

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        pos = event.position()

        # Tooltip check for markers
        hovered_event = None
        for rect, ev in self._marker_rects:
            if rect.contains(pos):
                hovered_event = ev
                break

        if hovered_event:
            time_str = to_iso8601(hovered_event.normalized_timestamp_utc) or hovered_event.raw_timestamp or "N/A"
            tip_text = f"<b>{hovered_event.event_type}</b><br>{hovered_event.description or ''}<br><i>Time: {time_str}</i>"
            QToolTip.showText(event.globalPosition().toPoint(), tip_text, self)
        else:
            QToolTip.hideText()

        if self._is_dragging:
            self._update_position_from_mouse(event.position().x())

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton and self._is_dragging:
            self._is_dragging = False
            self._update_position_from_mouse(event.position().x())

    def _update_position_from_mouse(self, mouse_x: float) -> None:
        margin_x = 24
        track_w = max(1.0, self.width() - (margin_x * 2))
        ratio = max(0.0, min(1.0, (mouse_x - margin_x) / track_w))
        new_pos = ratio * self._duration_seconds
        self.set_current_position(new_pos)
        self.position_changed.emit(new_pos)
