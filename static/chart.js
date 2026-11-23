/* Traffic chart: smooth filled lines for download and upload, drawn on a canvas.
 * Usage: drawTrafficChart(canvasElement, {labels, down, up}) */
(function () {
  const DOWN = "#1d4ed8";   // download (teal)
  const UP = "#d7191f";     // upload (yellow)

  function unitFor(max) {
    if (max >= 1024 * 1024) return {div: 1024 * 1024, name: "MB"};
    if (max >= 1024) return {div: 1024, name: "KB"};
    return {div: 1, name: "B"};
  }

  function niceStep(maxValue, ticks) {
    const raw = maxValue / ticks || 1;
    const pow = Math.pow(10, Math.floor(Math.log10(raw)));
    const f = raw / pow;
    const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
    return nice * pow;
  }

  // Smooth curve through points (Catmull-Rom converted to Bezier curves).
  function smoothPath(ctx, pts) {
    ctx.moveTo(pts[0].x, pts[0].y);
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[i - 1] || pts[i];
      const p1 = pts[i];
      const p2 = pts[i + 1];
      const p3 = pts[i + 2] || p2;
      const c1x = p1.x + (p2.x - p0.x) / 6, c1y = p1.y + (p2.y - p0.y) / 6;
      const c2x = p2.x - (p3.x - p1.x) / 6, c2y = p2.y - (p3.y - p1.y) / 6;
      ctx.bezierCurveTo(c1x, c1y, c2x, c2y, p2.x, p2.y);
    }
  }

  function drawTrafficChart(canvas, series) {
    const dpr = window.devicePixelRatio || 1;
    // Fit inside the container's padding, so the chart never runs past the card edge.
    const host = canvas.parentElement;
    const pad = getComputedStyle(host);
    const cssWidth = (host.clientWidth - parseFloat(pad.paddingLeft) - parseFloat(pad.paddingRight)) || 600;
    const cssHeight = Math.min(320, Math.max(220, Math.round(cssWidth * 0.45)));
    canvas.style.width = cssWidth + "px";
    canvas.style.height = cssHeight + "px";
    canvas.width = Math.round(cssWidth * dpr);
    canvas.height = Math.round(cssHeight * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssWidth, cssHeight);

    const textColor = getComputedStyle(canvas).color || "#8a8a8a";
    const gridColor = "rgba(139,147,167,0.25)";
    const left = 62, right = 12, top = 16, bottom = 30;
    const w = cssWidth - left - right, h = cssHeight - top - bottom;

    const n = series.labels.length;
    const maxRaw = Math.max(1, ...series.down, ...series.up);
    const unit = unitFor(maxRaw);
    const maxVal = maxRaw / unit.div;
    const step = niceStep(maxVal * 1.1, 5);
    const yMax = Math.ceil((maxVal * 1.1) / step) * step;

    const x = (i) => left + (n <= 1 ? w / 2 : (i / (n - 1)) * w);
    const y = (v) => top + h - (v / unit.div / yMax) * h;

    // Grid and Y labels.
    ctx.font = "12px system-ui, sans-serif";
    ctx.fillStyle = textColor;
    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    for (let v = 0; v <= yMax + 1e-9; v += step) {
      const yy = top + h - (v / yMax) * h;
      ctx.beginPath(); ctx.moveTo(left, yy); ctx.lineTo(left + w, yy); ctx.stroke();
      ctx.textAlign = "right"; ctx.textBaseline = "middle";
      ctx.fillText(`${v.toFixed(1)}${unit.name}`, left - 8, yy);
    }
    // Time labels: at most about 8 across the chart.
    const every = Math.max(1, Math.ceil(n / 8));
    ctx.textAlign = "center"; ctx.textBaseline = "top";
    for (let i = 0; i < n; i += every) {
      ctx.beginPath(); ctx.moveTo(x(i), top); ctx.lineTo(x(i), top + h); ctx.stroke();
      ctx.fillText(series.labels[i], x(i), top + h + 8);
    }

    // Filled areas and lines: draw upload first so download sits on top.
    const drawSeries = (values, color, fill) => {
      const pts = values.map((v, i) => ({x: x(i), y: y(v)}));
      if (!pts.length) return;
      ctx.beginPath();
      smoothPath(ctx, pts);
      ctx.lineTo(x(n - 1), top + h);
      ctx.lineTo(x(0), top + h);
      ctx.closePath();
      ctx.fillStyle = fill; ctx.fill();

      ctx.beginPath();
      smoothPath(ctx, pts);
      ctx.strokeStyle = color; ctx.lineWidth = 2.5; ctx.stroke();

      ctx.fillStyle = color;
      pts.forEach((p, i) => {
        if (values[i] > 0 || i === pts.length - 1) {
          ctx.beginPath(); ctx.arc(p.x, p.y, 4.5, 0, Math.PI * 2); ctx.fill();
        }
      });
    };
    drawSeries(series.up, UP, "rgba(215,25,31,0.18)");
    drawSeries(series.down, DOWN, "rgba(29,78,216,0.18)");

    // Legend with totals for the period.
    const sum = (a) => a.reduce((s, v) => s + v, 0);
    const fmt = (bytes) => {
      if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + " MB";
      if (bytes >= 1024) return (bytes / 1024).toFixed(1) + " KB";
      return bytes + " B";
    };
    ctx.textAlign = "left"; ctx.textBaseline = "middle";
    const legend = [["Download", DOWN, sum(series.down)], ["Upload", UP, sum(series.up)]];
    let lx = left;
    legend.forEach(([label, color, total]) => {
      ctx.fillStyle = color; ctx.fillRect(lx, 6, 12, 4);
      ctx.fillStyle = textColor;
      const text = `${label}: ${fmt(total)}`;
      ctx.fillText(text, lx + 18, 8);
      lx += ctx.measureText(text).width + 40;
    });
  }

  window.drawTrafficChart = drawTrafficChart;
})();
