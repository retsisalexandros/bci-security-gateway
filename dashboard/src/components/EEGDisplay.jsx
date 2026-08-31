import { useRef, useEffect } from "react";

const TRACE = "#2fbfa0";
const GRID = "rgba(47, 191, 160, 0.06)";
const BG = "#080b0f";
const LABEL = "#7f8b95";
const DISPLAY_SECONDS = 4;
const CANVAS_H_PER_CH = 50;

export default function EEGDisplay({ packets }) {
  const canvasRef = useRef(null);
  const bufferRef = useRef([]);

  useEffect(() => {
    if (packets.length === 0) return;
    const buf = bufferRef.current;
    for (const pkt of packets) {
      buf.push(pkt.channels);
    }
    const maxSamples = 250 * DISPLAY_SECONDS;
    if (buf.length > maxSamples) {
      bufferRef.current = buf.slice(buf.length - maxSamples);
    }
  }, [packets]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let rafId;

    const draw = () => {
      const buf = bufferRef.current;
      const w = canvas.width;
      const h = canvas.height;
      const numCh = 8;
      const chHeight = h / numCh;

      ctx.fillStyle = BG;
      ctx.fillRect(0, 0, w, h);

      ctx.strokeStyle = GRID;
      ctx.lineWidth = 1;
      for (let ch = 0; ch <= numCh; ch++) {
        const y = chHeight * ch;
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }
      const divs = 8;
      for (let d = 0; d <= divs; d++) {
        const x = (d / divs) * w;
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }

      ctx.fillStyle = LABEL;
      ctx.font = "10px ui-monospace, monospace";
      for (let ch = 0; ch < numCh; ch++) {
        ctx.fillText(`CH${ch + 1}`, 5, chHeight * ch + 13);
      }

      if (buf.length < 2) {
        rafId = requestAnimationFrame(draw);
        return;
      }

      const samplesOnScreen = Math.min(buf.length, w);
      const startIdx = buf.length - samplesOnScreen;

      ctx.strokeStyle = TRACE;
      ctx.shadowColor = TRACE;
      ctx.shadowBlur = 3;
      ctx.lineWidth = 1.1;
      for (let ch = 0; ch < numCh; ch++) {
        const yCenter = chHeight * ch + chHeight / 2;
        ctx.beginPath();
        for (let i = 0; i < samplesOnScreen; i++) {
          const x = (i / samplesOnScreen) * w;
          const val = buf[startIdx + i][ch] || 0;
          const y = yCenter - (val / 100) * (chHeight * 0.4);
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.stroke();
      }
      ctx.shadowBlur = 0;

      rafId = requestAnimationFrame(draw);
    };

    draw();
    return () => cancelAnimationFrame(rafId);
  }, []);

  return (
    <div className="panel">
      <h2>EEG Signal</h2>
      <canvas
        ref={canvasRef}
        width={700}
        height={CANVAS_H_PER_CH * 8}
        style={{ width: "100%", height: CANVAS_H_PER_CH * 8, background: BG, borderRadius: 4 }}
      />
    </div>
  );
}
