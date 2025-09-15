'use client';

import { useEffect, useRef, useState } from 'react';

const steps = [
  {
    number: 1,
    title: 'Bound',
    description: 'Define exact scope and success metrics',
  },
  {
    number: 2,
    title: 'Architect',
    description: 'Design focused tensor architectures',
  },
  {
    number: 3,
    title: 'Deploy',
    description: 'Implement with surgical precision',
  },
  {
    number: 4,
    title: 'Measure',
    description: 'Track specific, quantifiable outcomes',
  },
];

export default function MethodSection() {
  const [visibleSteps, setVisibleSteps] = useState<number[]>([]);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            steps.forEach((_, index) => {
              setTimeout(() => {
                setVisibleSteps((prev) => [...prev, index]);
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
    <section id="method" ref={sectionRef} className="section-padding relative">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-5xl md:text-6xl font-bold mb-6">
            <span className="gradient-text">From Problem to Production</span>
          </h2>
        </div>

        <div className="max-w-4xl mx-auto space-y-8">
          {steps.map((step, index) => (
            <div
              key={index}
              className={`transition-all duration-700 ${
                visibleSteps.includes(index)
                  ? 'opacity-100 translate-x-0'
                  : 'opacity-0 translate-x-10'
              }`}
            >
              <div className="flex items-start border-l-2 border-gray-800 hover:border-blue-500 transition-colors duration-300 pl-8 py-6">
                <div className="flex-shrink-0 mr-6">
                  <div className="text-3xl font-mono text-blue-400 mb-2">
                    {step.number.toString().padStart(2, '0')}
                  </div>
                </div>
                <div>
                  <h3 className="text-2xl font-bold mb-3 text-white">{step.title}</h3>
                  <p className="text-lg text-gray-400 leading-relaxed">{step.description}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-16 text-center">
          <div className="glass p-8 max-w-4xl mx-auto">
            <div className="text-2xl font-mono text-blue-400 mb-4">
              Bound → Architect → Deploy → Measure
            </div>
            <p className="text-gray-400 text-lg leading-relaxed">
              Our systematic approach ensures every solution is bounded, complete, and measurable.
              No scope creep, no feature bloat - just focused AI that works.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}