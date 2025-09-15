'use client';

import { useEffect, useRef, useState } from 'react';

const valueProps = [
  {
    title: 'Finite Scope',
    description: 'Every solution has clearly defined boundaries and success metrics',
    metric: 'Bounded',
    icon: (
      <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
  {
    title: 'Complete Depth',
    description: '100% automation within scope, not 10% across everything',
    metric: '100%',
    icon: (
      <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
      </svg>
    ),
  },
  {
    title: 'Measurable Impact',
    description: 'Bounded problems produce measurable, predictable ROI',
    metric: 'Proven',
    icon: (
      <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    ),
  },
  {
    title: 'Resource Efficient',
    description: 'Finite compute resources, infinite optimization within constraints',
    metric: 'Optimized',
    icon: (
      <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
  },
];

export default function ValuePropositionSection() {
  const [visibleCards, setVisibleCards] = useState<number[]>([]);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            valueProps.forEach((_, index) => {
              setTimeout(() => {
                setVisibleCards((prev) => [...prev, index]);
              }, index * 150);
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
    <section id="value" ref={sectionRef} className="section-padding relative">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-5xl md:text-6xl font-bold mb-6">
            <span className="gradient-text">The Finite Advantage</span>
          </h2>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto">
            Mathematical precision applied to business automation
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          {valueProps.map((prop, index) => (
            <div
              key={index}
              className={`glass p-6 text-center transition-all duration-700 ${
                visibleCards.includes(index)
                  ? 'opacity-100 translate-y-0'
                  : 'opacity-0 translate-y-10'
              }`}
            >
              <div className="text-gray-400 mb-4 flex justify-center">{prop.icon}</div>
              <div className="text-2xl font-bold text-blue-400 mb-2 font-mono">{prop.metric}</div>
              <h3 className="text-lg font-semibold text-white mb-3">{prop.title}</h3>
              <p className="text-sm text-gray-400 leading-relaxed">{prop.description}</p>
            </div>
          ))}
        </div>

        <div className="glass p-8 max-w-4xl mx-auto text-center">
          <div className="text-3xl font-mono text-blue-400 mb-4">
            lim<sub className="text-lg">scope→finite</sub> (quality) = ∞
          </div>
          <h3 className="text-2xl font-semibold text-white mb-4">
            As scope approaches finite, quality approaches infinite
          </h3>
          <p className="text-gray-400 leading-relaxed">
            In mathematics, as we constrain the domain of a function, we can achieve perfect optimization
            within those bounds. Fynsor applies this principle to AI: by defining finite boundaries,
            we deliver infinite quality within scope.
          </p>
        </div>
      </div>
    </section>
  );
}