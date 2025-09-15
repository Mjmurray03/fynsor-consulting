'use client';

import { useEffect, useRef, useState } from 'react';

const technicalLayers = [
  {
    title: 'Data Layer',
    capabilities: [
      'Direct API connections to financial platforms',
      'Automated data extraction and validation',
      'Real-time streaming pipelines',
      'Multi-source data reconciliation'
    ],
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
      </svg>
    ),
  },
  {
    title: 'AI Layer',
    capabilities: [
      'Fine-tuned language models for finance',
      'Custom agent architectures',
      'Retrieval-augmented generation (RAG)',
      'Specialized small language models (SLMs)'
    ],
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
      </svg>
    ),
  },
  {
    title: 'Integration Layer',
    capabilities: [
      'Enterprise system connectivity',
      'Workflow automation frameworks',
      'Event-driven architectures',
      'Scalable microservices'
    ],
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
      </svg>
    ),
  },
];

export default function TechnicalSection() {
  const [visibleLayers, setVisibleLayers] = useState<number[]>([]);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            technicalLayers.forEach((_, index) => {
              setTimeout(() => {
                setVisibleLayers((prev) => [...prev, index]);
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
    <section id="technical" ref={sectionRef} className="section-padding relative">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-5xl md:text-6xl font-bold mb-4">
            <span className="gradient-text">Technical Architecture</span>
          </h2>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto">
            Three-layer architecture designed for enterprise-scale financial automation
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {technicalLayers.map((layer, index) => (
            <div
              key={index}
              className={`glass p-8 transition-all duration-700 ${
                visibleLayers.includes(index)
                  ? 'opacity-100 translate-y-0'
                  : 'opacity-0 translate-y-10'
              }`}
            >
              <div className="flex items-center mb-6">
                <div className="text-gray-400 mr-3">{layer.icon}</div>
                <h3 className="text-xl font-semibold text-white">{layer.title}</h3>
              </div>

              <div className="space-y-3">
                {layer.capabilities.map((capability, capIndex) => (
                  <div
                    key={capIndex}
                    className="flex items-start text-sm text-gray-400"
                  >
                    <div className="w-1.5 h-1.5 bg-blue-500 rounded-full mr-3 mt-2 flex-shrink-0"></div>
                    <span>{capability}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="mt-16 text-center">
          <div className="glass p-8 max-w-4xl mx-auto">
            <h3 className="text-2xl font-semibold text-white mb-4">
              Intelligent Systems at Scale
            </h3>
            <p className="text-gray-400 leading-relaxed">
              We architect intelligent systems that operate at the intersection of financial expertise and artificial intelligence.
              Our solutions leverage fine-tuned language models and custom agents to deliver domain-specific automation at scale.
              From raw data acquisition to intelligent processing, we build end-to-end systems that transform how financial institutions operate.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}