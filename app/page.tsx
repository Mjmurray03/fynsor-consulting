'use client';

import React, { useEffect, useState } from 'react';
import Layout from '../components/layout/Layout';
import Section from '../components/ui/Section';
import TensorLogo from '../components/animations/TensorLogo';

const HomePage: React.FC = () => {
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    setIsLoaded(true);
  }, []);

  return (
    <Layout>
      {/* Hero Section */}
      <Section className="min-h-screen flex items-center justify-center bg-white">
        <div className="text-center max-w-4xl mx-auto">
          {/* Animated Tensor Logo */}
          <div className={`
            flex justify-center mb-12 transition-all duration-1000
            ${isLoaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}
          `}>
            <TensorLogo size={120} animate={isLoaded} />
          </div>

          {/* Company Name */}
          <h1 className={`
            text-6xl md:text-8xl font-bold text-black mb-6 font-inter
            transition-all duration-1000 delay-300
            ${isLoaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}
          `}>
            Fynsor
          </h1>

          {/* Tagline */}
          <p className={`
            text-xl md:text-2xl text-gray-600 mb-12 font-inter
            transition-all duration-1000 delay-600
            ${isLoaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}
          `}>
            Where Finance Meets Intelligence
          </p>

          {/* Description */}
          <div className={`
            max-w-2xl mx-auto text-gray-700 text-lg leading-relaxed
            transition-all duration-1000 delay-900
            ${isLoaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}
          `}>
            <p className="mb-6">
              Institutional-grade commercial real estate financial modeling
              and analysis powered by advanced computational intelligence.
            </p>
            <p>
              Delivering precision, transparency, and insight for sophisticated
              real estate investment decisions.
            </p>
          </div>
        </div>
      </Section>

      {/* Value Proposition Section */}
      <Section className="bg-gray-50">
        <div className="grid md:grid-cols-3 gap-12">
          <div className="text-center">
            <div className="mb-6 flex justify-center">
              <div className="w-16 h-16 border border-gray-600 flex items-center justify-center">
                <TensorLogo size={32} />
              </div>
            </div>
            <h3 className="text-xl font-semibold text-black mb-4 font-inter">
              Institutional Standards
            </h3>
            <p className="text-gray-600 leading-relaxed">
              Built to meet the rigorous requirements of institutional investors
              with enterprise-grade security and compliance.
            </p>
          </div>

          <div className="text-center">
            <div className="mb-6 flex justify-center">
              <div className="w-16 h-16 border border-gray-600 flex items-center justify-center">
                <div className="w-8 h-8 grid grid-cols-2 gap-1">
                  <div className="bg-black rounded-sm"></div>
                  <div className="bg-gray-400 rounded-sm"></div>
                  <div className="bg-gray-400 rounded-sm"></div>
                  <div className="bg-black rounded-sm"></div>
                </div>
              </div>
            </div>
            <h3 className="text-xl font-semibold text-black mb-4 font-inter">
              Advanced Analytics
            </h3>
            <p className="text-gray-600 leading-relaxed">
              Sophisticated financial modeling leveraging tensor-based computations
              for complex real estate scenarios.
            </p>
          </div>

          <div className="text-center">
            <div className="mb-6 flex justify-center">
              <div className="w-16 h-16 border border-gray-600 flex items-center justify-center">
                <div className="w-8 h-8 grid grid-cols-3 gap-px">
                  {Array.from({ length: 9 }).map((_, i) => (
                    <div key={i} className="bg-gray-400 rounded-sm"></div>
                  ))}
                </div>
              </div>
            </div>
            <h3 className="text-xl font-semibold text-black mb-4 font-inter">
              Comprehensive Coverage
            </h3>
            <p className="text-gray-600 leading-relaxed">
              Complete analysis across all major commercial real estate asset
              classes and investment strategies.
            </p>
          </div>
        </div>
      </Section>
    </Layout>
  );
};

export default HomePage;