'use client';

import React from 'react';
import Layout from '../../components/layout/Layout';
import Section from '../../components/ui/Section';
import TensorLogo from '../../components/animations/TensorLogo';

const ServicesPage: React.FC = () => {
  const propertyTypes = [
    {
      title: 'Office',
      description: 'Class A/B/C office buildings, medical office, corporate campuses',
      features: ['Lease rollover analysis', 'Market rent projections', 'Tenant credit evaluation']
    },
    {
      title: 'Retail',
      description: 'Shopping centers, strip malls, single-tenant net lease properties',
      features: ['Sales productivity analysis', 'Anchor tenant impact', 'Market saturation modeling']
    },
    {
      title: 'Industrial',
      description: 'Warehouses, distribution centers, manufacturing facilities',
      features: ['Logistics demand forecasting', 'Automation impact analysis', 'Supply chain optimization']
    },
    {
      title: 'Multifamily',
      description: 'Apartment complexes, student housing, senior living facilities',
      features: ['Demographic trend analysis', 'Rent growth projections', 'Operating expense optimization']
    },
    {
      title: 'Hospitality',
      description: 'Hotels, resorts, extended stay properties',
      features: ['RevPAR analysis', 'Market penetration studies', 'Capital expenditure planning']
    },
    {
      title: 'Healthcare',
      description: 'Hospitals, outpatient facilities, skilled nursing',
      features: ['Regulatory compliance analysis', 'Reimbursement modeling', 'Demographics impact']
    }
  ];

  const modelingCapabilities = [
    {
      title: 'Cash Flow Modeling',
      description: 'Detailed 10+ year DCF models with scenario analysis and sensitivity testing',
      icon: '📊'
    },
    {
      title: 'Market Analysis',
      description: 'Comprehensive market studies incorporating economic and demographic trends',
      icon: '📈'
    },
    {
      title: 'Risk Assessment',
      description: 'Monte Carlo simulations and stress testing for comprehensive risk evaluation',
      icon: '⚡'
    },
    {
      title: 'Portfolio Optimization',
      description: 'Multi-asset portfolio analysis with correlation and diversification metrics',
      icon: '🎯'
    },
    {
      title: 'Valuation Services',
      description: 'Income, sales comparison, and cost approach methodologies',
      icon: '💎'
    },
    {
      title: 'Investment Structuring',
      description: 'Complex deal structuring with tax optimization and return enhancement',
      icon: '🏗️'
    }
  ];

  return (
    <Layout>
      {/* Header Section */}
      <Section className="bg-white">
        <div className="text-center max-w-4xl mx-auto">
          <div className="flex justify-center mb-8">
            <TensorLogo size={80} />
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-black mb-6 font-inter">
            Services
          </h1>
          <p className="text-xl text-gray-600 leading-relaxed">
            Comprehensive commercial real estate financial modeling and analysis
            across all major property types and investment strategies.
          </p>
        </div>
      </Section>

      {/* Property Types Section */}
      <Section className="bg-gray-50">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-black mb-12 text-center font-inter">
            Property Type Expertise
          </h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {propertyTypes.map((type, index) => (
              <div key={index} className="bg-white border border-gray-200 p-6 hover:border-gray-400 transition-colors duration-200">
                <div className="flex items-center mb-4">
                  <div className="w-8 h-8 border border-gray-600 flex items-center justify-center mr-3">
                    <div className="w-3 h-3 bg-black rounded-sm"></div>
                  </div>
                  <h3 className="text-xl font-semibold text-black font-inter">
                    {type.title}
                  </h3>
                </div>
                <p className="text-gray-700 mb-4 leading-relaxed">
                  {type.description}
                </p>
                <ul className="space-y-2">
                  {type.features.map((feature, idx) => (
                    <li key={idx} className="text-sm text-gray-600 flex items-center">
                      <div className="w-1 h-1 bg-gray-400 rounded-full mr-3"></div>
                      {feature}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </Section>

      {/* Financial Modeling Capabilities */}
      <Section className="bg-white">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-black mb-12 text-center font-inter">
            Financial Modeling Capabilities
          </h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {modelingCapabilities.map((capability, index) => (
              <div key={index} className="text-center p-6">
                <div className="mb-6 flex justify-center">
                  <div className="w-16 h-16 border border-gray-600 flex items-center justify-center">
                    <TensorLogo size={32} />
                  </div>
                </div>
                <h3 className="text-xl font-semibold text-black mb-4 font-inter">
                  {capability.title}
                </h3>
                <p className="text-gray-700 leading-relaxed">
                  {capability.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </Section>

      {/* Advanced Analytics Section */}
      <Section className="bg-gray-50">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl font-bold text-black mb-12 text-center font-inter">
            Advanced Analytics Framework
          </h2>
          <div className="space-y-12">
            <div className="grid md:grid-cols-2 gap-12 items-center">
              <div>
                <h3 className="text-2xl font-semibold text-black mb-6 font-inter">
                  Tensor-Based Computations
                </h3>
                <p className="text-gray-700 leading-relaxed mb-4">
                  Leveraging multidimensional tensor analysis to process complex relationships
                  between market variables, property characteristics, and financial performance.
                </p>
                <p className="text-gray-700 leading-relaxed">
                  This advanced mathematical framework enables simultaneous analysis of hundreds
                  of variables while maintaining computational efficiency and numerical stability.
                </p>
              </div>
              <div className="flex justify-center">
                <div className="grid grid-cols-4 gap-2">
                  {Array.from({ length: 16 }).map((_, i) => (
                    <div key={i} className={`
                      w-6 h-6 border border-gray-400 transition-all duration-300
                      ${Math.random() > 0.5 ? 'bg-black' : 'bg-white'}
                    `}></div>
                  ))}
                </div>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-12 items-center">
              <div className="md:order-2">
                <h3 className="text-2xl font-semibold text-black mb-6 font-inter">
                  Machine Learning Integration
                </h3>
                <p className="text-gray-700 leading-relaxed mb-4">
                  Incorporating supervised and unsupervised learning algorithms to identify
                  patterns in historical data and improve forecasting accuracy.
                </p>
                <p className="text-gray-700 leading-relaxed">
                  Continuous model refinement through backtesting and validation against
                  actual market performance ensures robust predictive capabilities.
                </p>
              </div>
              <div className="md:order-1 flex justify-center">
                <div className="space-y-2">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="flex space-x-2">
                      {Array.from({ length: 8 }).map((_, j) => (
                        <div key={j} className={`
                          w-3 h-3 border border-gray-400
                          ${(i + j) % 3 === 0 ? 'bg-black' : 'bg-white'}
                        `}></div>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* CTA Section */}
      <Section className="bg-white">
        <div className="text-center max-w-3xl mx-auto">
          <h2 className="text-3xl font-bold text-black mb-8 font-inter">
            Ready to Transform Your Analysis?
          </h2>
          <p className="text-lg text-gray-700 leading-relaxed mb-8">
            Experience the power of institutional-grade financial modeling
            enhanced by advanced computational intelligence.
          </p>
          <div className="flex justify-center">
            <TensorLogo size={60} animate />
          </div>
        </div>
      </Section>
    </Layout>
  );
};

export default ServicesPage;