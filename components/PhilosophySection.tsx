'use client';

import { useEffect, useRef, useState } from 'react';

export default function PhilosophySection() {
  const [isVisible, setIsVisible] = useState(false);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setIsVisible(true);
          }
        });
      },
      { threshold: 0.1 }
    );

    if (sectionRef.current) {
      observer.observe(sectionRef.current);
    }

    return () => observer.disconnect();
  }, []);

  return (
    <section id="philosophy" ref={sectionRef} className="section-padding relative">
      <div className="container mx-auto px-4 max-w-5xl">
        <div className={`text-center mb-16 transition-all duration-1000 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
          <h2 className="text-5xl md:text-6xl font-bold mb-6">
            <span className="gradient-text">The Power of Bounded Intelligence</span>
          </h2>
        </div>

        <div className={`grid grid-cols-1 lg:grid-cols-2 gap-16 items-center transition-all duration-1000 delay-300 ${isVisible ? 'opacity-100' : 'opacity-0'}`}>
          <div className="space-y-6">
            <p className="text-lg text-gray-300 leading-relaxed">
              At Fynsor, we apply the principles of finite mathematics to artificial intelligence.
              Every tensor operation, every model we deploy, every system we architect exists within
              carefully defined boundaries.
            </p>
            <p className="text-lg text-gray-400 leading-relaxed">
              This isn't a limitation - it's our competitive advantage.
            </p>
            <p className="text-lg text-gray-300 leading-relaxed">
              We believe in the Unix philosophy for the AI age: tools that do one thing and do it
              exceptionally well. Our solutions are finite in scope but infinite in depth, delivering
              complete automation for specific workflows rather than partial automation for everything.
            </p>
          </div>

          <div className="glass p-8">
            <div className="text-center mb-6">
              <div className="text-4xl font-mono text-blue-400 mb-2">∞ → ℝⁿ</div>
              <div className="text-sm text-gray-500 uppercase tracking-wide">Infinite to Finite</div>
            </div>
            <div className="space-y-4 text-sm text-gray-400">
              <div className="flex items-center justify-between border-b border-gray-800 pb-2">
                <span>Scope</span>
                <span className="text-white font-mono">Bounded</span>
              </div>
              <div className="flex items-center justify-between border-b border-gray-800 pb-2">
                <span>Depth</span>
                <span className="text-white font-mono">Complete</span>
              </div>
              <div className="flex items-center justify-between border-b border-gray-800 pb-2">
                <span>Output</span>
                <span className="text-white font-mono">Deterministic</span>
              </div>
              <div className="flex items-center justify-between">
                <span>ROI</span>
                <span className="text-white font-mono">Measurable</span>
              </div>
            </div>
          </div>
        </div>

        <div className={`mt-16 text-center transition-all duration-1000 delay-600 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
          <div className="inline-flex items-center space-x-4 text-sm text-gray-500">
            <span>FYNSOR</span>
            <span>=</span>
            <span className="text-gray-400">FINITE</span>
            <span>+</span>
            <span className="text-gray-400">TENSOR</span>
          </div>
        </div>
      </div>
    </section>
  );
}