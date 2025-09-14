'use client';

import React from 'react';
import Layout from '../../components/layout/Layout';
import Section from '../../components/ui/Section';
import TensorLogo from '../../components/animations/TensorLogo';

const InsightsPage: React.FC = () => {
  return (
    <Layout>
      {/* Header Section */}
      <Section className="bg-white">
        <div className="text-center max-w-4xl mx-auto">
          <div className="flex justify-center mb-8">
            <TensorLogo size={80} />
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-black mb-6 font-inter">
            Insights
          </h1>
          <p className="text-xl text-gray-600 leading-relaxed">
            Market intelligence and analytical insights powered by advanced
            computational methods and institutional-grade research.
          </p>
        </div>
      </Section>

      {/* Coming Soon Section */}
      <Section className="bg-gray-50">
        <div className="text-center max-w-3xl mx-auto">
          <div className="mb-8 flex justify-center">
            <TensorLogo size={120} animate />
          </div>
          <h2 className="text-3xl font-bold text-black mb-6 font-inter">
            Coming Soon
          </h2>
          <p className="text-lg text-gray-700 leading-relaxed mb-8">
            Our insights platform is currently under development, featuring
            real-time market analysis, trend identification, and predictive
            modeling across commercial real estate sectors.
          </p>
          <div className="space-y-6 text-gray-600">
            <div className="flex items-center justify-center space-x-3">
              <div className="w-2 h-2 bg-gray-400 rounded-full"></div>
              <span>Market trend analysis and forecasting</span>
            </div>
            <div className="flex items-center justify-center space-x-3">
              <div className="w-2 h-2 bg-gray-400 rounded-full"></div>
              <span>Comparative market studies and benchmarking</span>
            </div>
            <div className="flex items-center justify-center space-x-3">
              <div className="w-2 h-2 bg-gray-400 rounded-full"></div>
              <span>Investment opportunity identification</span>
            </div>
            <div className="flex items-center justify-center space-x-3">
              <div className="w-2 h-2 bg-gray-400 rounded-full"></div>
              <span>Risk assessment and scenario modeling</span>
            </div>
          </div>
        </div>
      </Section>
    </Layout>
  );
};

export default InsightsPage;