'use client';

import { useEffect, useRef, useState } from 'react';

const methodSteps = [
  {
    number: '1',
    title: 'BOUND THE PROBLEM',
    description: 'Define exact boundaries, inputs, outputs, and success criteria',
    details: [
      'Identify single workflow for complete automation',
      'Map finite input/output relationships',
      'Establish measurable success metrics',
      'Define computational resource constraints'
    ],
  },
  {
    number: '2',
    title: 'ARCHITECT THE SOLUTION',
    description: 'Design focused tensor architectures optimized for your specific task',
    details: [
      'Custom neural network architectures',
      'Optimize tensor operations for specific computations',
      'Select appropriate model sizes and complexities',
      'Design deterministic processing pipelines'
    ],
  },
  {
    number: '3',
    title: 'DEPLOY WITH PRECISION',
    description: 'Implement bounded systems with complete depth within scope',
    details: [
      'Production-ready deployment within constraints',
      'Comprehensive automation of defined workflow',
      'Real-time monitoring and performance tracking',
      'Fail-safe mechanisms for edge cases'
    ],
  },
  {
    number: '4',
    title: 'MEASURE FINITE OUTCOMES',
    description: 'Track specific, measurable improvements against defined metrics',
    details: [
      'Quantify performance within bounded scope',
      'ROI measurement against baseline metrics',
      'Continuous optimization within constraints',
      'Predictable, repeatable results'
    ],
  },
];

export default function ApproachSection() {
  const [visibleSteps, setVisibleSteps] = useState<number[]>([]);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            methodSteps.forEach((_, index) => {
              setTimeout(() => {
                setVisibleSteps((prev) => [...prev, index]);
              }, index * 300);
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
    <section id="approach" ref={sectionRef} className="section-padding relative">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-5xl md:text-6xl font-bold mb-6">
            <span className="gradient-text">The Fynsor Method</span>
          </h2>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto">
            Systematic approach to deploying bounded AI solutions with complete depth
          </p>
        </div>

        <div className="space-y-8">
          {methodSteps.map((step, index) => (
            <div
              key={index}
              className={`transition-all duration-1000 ${
                visibleSteps.includes(index)
                  ? 'opacity-100 translate-x-0'
                  : 'opacity-0 translate-x-10'
              }`}
            >
              <div className="glass p-8">
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
                  <div className="lg:col-span-1">
                    <div className="flex items-center mb-4">
                      <div className="w-12 h-12 bg-blue-600 text-white rounded-none flex items-center justify-center text-xl font-bold mr-4">
                        {step.number}
                      </div>
                      <div>
                        <h3 className="text-xl font-bold text-white">{step.title}</h3>
                      </div>
                    </div>
                    <p className="text-gray-400 leading-relaxed">{step.description}</p>
                  </div>

                  <div className="lg:col-span-2">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {step.details.map((detail, detailIndex) => (
                        <div key={detailIndex} className="flex items-start">
                          <div className="w-2 h-2 bg-blue-500 rounded-full mr-3 mt-2 flex-shrink-0"></div>
                          <span className="text-sm text-gray-300">{detail}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-16 text-center">
          <div className="glass p-8 max-w-4xl mx-auto">
            <div className="text-2xl font-mono text-blue-400 mb-4">
              ƒ: Bounded → Complete
            </div>
            <h3 className="text-2xl font-semibold text-white mb-4">
              Infinite Possibilities. Finite Applications. Exceptional Results.
            </h3>
            <p className="text-gray-400 leading-relaxed">
              In mathematics, finite systems can be fully understood, proven, and trusted.
              We bring this same rigor to AI. Every Fynsor solution is bounded, complete,
              and exceptional within its scope.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}