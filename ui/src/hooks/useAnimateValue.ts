import { useEffect, useState, useRef } from 'react';

export function useAnimateValue(value: number, duration = 500) {
  const [displayValue, setDisplayValue] = useState(value);
  const startTime = useRef<number | null>(null);
  const startValue = useRef(value);
  const targetValue = useRef(value);

  useEffect(() => {
    if (value === targetValue.current) return;

    startValue.current = displayValue;
    targetValue.current = value;
    startTime.current = null;

    let animationFrame: number;

    const step = (timestamp: number) => {
      if (!startTime.current) startTime.current = timestamp;
      const elapsed = timestamp - startTime.current;
      const progress = Math.min(elapsed / duration, 1);
      
      const current = Math.floor(startValue.current + (value - startValue.current) * progress);
      setDisplayValue(current);

      if (progress < 1) {
        animationFrame = requestAnimationFrame(step);
      }
    };

    animationFrame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animationFrame);
  }, [value, duration]);

  return displayValue;
}
