'use client';

import { useEffect, useRef, useState } from 'react';

const insights = [
  {
    metric: 'Orders of Magnitude',
    label: 'Efficiency Improvement',
    description: 'Reduction in manual processing time through intelligent automation',
  },
  {
    metric: 'Sub-Second',
    label: 'Response Times',
    description: 'Real-time data processing and intelligent decision support',
  },
  {
    metric: 'Enterprise-Scale',
    label: 'System Architecture',
    description: 'Scalable AI frameworks designed for institutional workloads',
  },
];

export default function InsightsSection() {
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
    <section id="insights" ref={sectionRef} className="section-padding relative">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
          <div className={`transition-all duration-1000 ${isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-10'}`}>
            <h2 className="text-5xl md:text-6xl font-bold mb-6">
              <span className="gradient-text">Precision Automation for Institutional Finance</span>
            </h2>
            <p className="text-xl text-gray-400 mb-8 leading-relaxed">
              Fynsor architects intelligent systems that eliminate operational inefficiencies in financial workflows.
              We specialize in deploying custom AI agents, fine-tuned models, and automated data pipelines.
            </p>
            <p className="text-gray-400 mb-8 leading-relaxed">
              Our solutions access raw data directly from source systems, apply sophisticated ML transformations,
              and deliver structured intelligence - reducing manual intervention by orders of magnitude.
            </p>
            <div className="flex items-center space-x-6 text-sm text-gray-500">
              <span className="flex items-center">
                <svg className="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                Enterprise-Grade Security
              </span>
              <span className="flex items-center">
                <svg className="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                Scalable Architecture
              </span>
            </div>
          </div>

          <div className={`space-y-6 transition-all duration-1000 delay-200 ${isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-10'}`}>
            {insights.map((insight, index) => (
              <div
                key={index}
                className="glass p-6 hover-lift"
                style={{ animationDelay: `${index * 100}ms` }}
              >
                <div className="text-4xl font-bold text-white mb-2">{insight.metric}</div>
                <div className="text-lg font-semibold text-gray-300 mb-1">{insight.label}</div>
                <div className="text-sm text-gray-500">{insight.description}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}