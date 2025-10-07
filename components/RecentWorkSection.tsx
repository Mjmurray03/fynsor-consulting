'use client';

import { useEffect, useRef, useState } from 'react';

const caseStudies = [
  {
    title: 'Investment Intelligence Engine',
    industry: 'Financial Services',
    challenge: 'Client needed to analyze 5,000,000+ records to identify high-value opportunities from data sources',
    solution: 'Built automated classification system with multi-stage filtering pipeline and custom scoring algorithm',
    results: [
      { metric: 'Processed over 5 million records', value: 'in under 48 hours' },
      { metric: 'Identified 2,000 qualified opportunities', value: '(vs. 50-100 through manual review)' },
      { metric: '1,500+ hours saved', value: 'vs manual analysis' },
      { metric: '1100% ROI', value: 'on implementation cost' },
    ],
    techStack: 'Custom ML pipeline, MongoDB, automated ETL',
  },
  {
    title: 'Workflow Management Platform',
    industry: 'Real Estate',
    challenge: 'Team using Excel spreadsheets for deal pipeline - data conflicts, no collaboration, limited visibility',
    solution: 'Custom CRM with automated workflows, multi-user collaboration, and real-time analytics',
    results: [
      { metric: 'Eliminated data loss', value: 'from spreadsheet conflicts' },
      { metric: 'Real-time collaboration', value: 'for multiple team members' },
      { metric: 'Automated follow-up tracking', value: 'reduced response time' },
      { metric: 'Complete pipeline visibility', value: 'with conversion metrics' },
    ],
    techStack: 'No-code platform customization, automated workflows, API integrations',
  },
  {
    title: 'Multi-Source Data Integration',
    industry: 'Research & Analytics',
    challenge: 'Client needed structured data from 10+ disparate sources with varying formats and update frequencies',
    solution: 'Scalable data aggregation system with automated collection, normalization, and quality validation',
    results: [
      { metric: '10+ data sources', value: 'integrated and standardized' },
      { metric: '85% reduction', value: 'in manual data entry' },
      { metric: 'Automated updates', value: 'vs manual pulls' },
      { metric: 'Processing 400 records/minute', value: 'at scale' },
    ],
    techStack: 'API orchestration, batch processing, hybrid storage architecture',
  },
];

export default function RecentWorkSection() {
  const [visibleCards, setVisibleCards] = useState<number[]>([]);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            caseStudies.forEach((_, index) => {
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
    <section id="recent-work" ref={sectionRef} className="section-padding relative">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-5xl md:text-6xl font-bold mb-6">
            <span className="gradient-text">Recent Work</span>
          </h2>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto">
            Focused AI delivering measurable outcomes
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 max-w-7xl mx-auto">
          {caseStudies.map((study, index) => (
            <div
              key={index}
              className={`glass border border-gray-800 hover:border-blue-600 transition-all duration-700 ${
                visibleCards.includes(index)
                  ? 'opacity-100 translate-y-0'
                  : 'opacity-0 translate-y-10'
              }`}
            >
              <div className="p-8">
                {/* Industry Tag */}
                <div className="mb-4">
                  <span className="inline-block px-3 py-1 text-xs font-semibold text-blue-400 bg-blue-950 border border-blue-800 rounded">
                    {study.industry}
                  </span>
                </div>

                {/* Title */}
                <h3 className="text-2xl font-bold text-white mb-6">{study.title}</h3>

                {/* Challenge */}
                <div className="mb-6">
                  <h4 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-2">
                    Challenge
                  </h4>
                  <p className="text-gray-400 leading-relaxed">{study.challenge}</p>
                </div>

                {/* Solution */}
                <div className="mb-6">
                  <h4 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-2">
                    Solution
                  </h4>
                  <p className="text-gray-400 leading-relaxed">{study.solution}</p>
                </div>

                {/* Results */}
                <div className="mb-6">
                  <h4 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-3">
                    Results
                  </h4>
                  <ul className="space-y-2">
                    {study.results.map((result, resultIndex) => (
                      <li key={resultIndex} className="text-gray-400 text-sm leading-relaxed">
                        <span className="font-bold text-white">{result.metric}</span>{' '}
                        <span className="text-gray-500">{result.value}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Tech Stack */}
                <div className="pt-6 border-t border-gray-800">
                  <p className="text-xs text-gray-600">{study.techStack}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
