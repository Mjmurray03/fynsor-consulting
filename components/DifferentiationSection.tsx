'use client';

import { useEffect, useRef, useState } from 'react';

const comparisons = [
  {
    title: 'vs. General AI Platforms',
    their: 'They promise everything, deliver generalities',
    ours: 'We promise one thing, deliver excellence',
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
  {
    title: 'vs. Broad Automation Tools',
    their: 'They offer shallow integrations across many systems',
    ours: 'We offer deep integration into your critical workflow',
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
  },
  {
    title: 'vs. Custom Development',
    their: 'They build from scratch, slowly and expensively',
    ours: 'We deploy focused solutions, rapidly and efficiently',
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
];

export default function DifferentiationSection() {
  const [visibleCards, setVisibleCards] = useState<number[]>([]);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            comparisons.forEach((_, index) => {
              setTimeout(() => {
                setVisibleCards((prev) => [...prev, index]);
              }, index * 200);
            });
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
    <section id="differentiation" ref={sectionRef} className="section-padding relative">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-5xl md:text-6xl font-bold mb-4">
            <span className="gradient-text">Why Bounded Beats Boundless</span>
          </h2>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto">
            Focus creates capability. Constraints enable optimization. Boundaries deliver results.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {comparisons.map((comparison, index) => (
            <div
              key={index}
              className={`glass p-8 transition-all duration-700 ${
                visibleCards.includes(index)
                  ? 'opacity-100 translate-y-0'
                  : 'opacity-0 translate-y-10'
              }`}
            >
              <div className="flex items-center mb-6">
                <div className="text-gray-400 mr-3">{comparison.icon}</div>
                <h3 className="text-lg font-semibold text-white">{comparison.title}</h3>
              </div>

              <div className="space-y-6">
                <div className="border-l-2 border-red-500 pl-4">
                  <div className="text-xs text-red-400 uppercase tracking-wide mb-1">Others</div>
                  <p className="text-gray-400 text-sm">{comparison.their}</p>
                </div>

                <div className="border-l-2 border-green-500 pl-4">
                  <div className="text-xs text-green-400 uppercase tracking-wide mb-1">Fynsor</div>
                  <p className="text-white text-sm font-medium">{comparison.ours}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-16 text-center">
          <div className="glass p-8 max-w-3xl mx-auto">
            <div className="text-2xl font-mono text-blue-400 mb-4">∞ ⊄ Production</div>
            <p className="text-gray-400 text-sm">
              Infinite possibilities cannot be deployed in production.
              Finite solutions with complete depth deliver measurable business value.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}