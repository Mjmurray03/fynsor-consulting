'use client';

import React from 'react';
import Layout from '../../components/layout/Layout';
import Section from '../../components/ui/Section';
import TensorLogo from '../../components/animations/TensorLogo';

const AboutPage: React.FC = () => {
  return (
    <Layout>
      {/* Header Section */}
      <Section className="bg-white">
        <div className="text-center max-w-4xl mx-auto">
          <div className="flex justify-center mb-8">
            <TensorLogo size={80} />
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-black mb-6 font-inter">
            About Fynsor
          </h1>
          <p className="text-xl text-gray-600 leading-relaxed">
            Where Finance Meets Intelligence - Delivering institutional-grade
            commercial real estate analysis through advanced computational methods.
          </p>
        </div>
      </Section>

      {/* Name Origin Section */}
      <Section className="bg-gray-50">
        <div className="grid md:grid-cols-2 gap-16 items-center">
          <div>
            <h2 className="text-3xl font-bold text-black mb-6 font-inter">
              The Fynsor Name
            </h2>
            <div className="space-y-6 text-gray-700 leading-relaxed">
              <p>
                <strong className="text-black">Fynsor</strong> represents the fusion of two powerful concepts:
              </p>
              <div className="pl-6 border-l-2 border-gray-300">
                <p className="mb-4">
                  <strong className="text-black">Fyn</strong> - Derived from "Finance," representing our deep
                  expertise in financial analysis, modeling, and institutional investment standards.
                </p>
                <p>
                  <strong className="text-black">Sor</strong> - From "Tensor," reflecting our use of advanced
                  mathematical frameworks and computational intelligence to solve complex real estate challenges.
                </p>
              </div>
              <p>
                This synthesis embodies our commitment to bridging traditional financial expertise
                with cutting-edge analytical capabilities, delivering unprecedented insight and precision
                in commercial real estate investment decisions.
              </p>
            </div>
          </div>
          <div className="flex justify-center">
            <div className="text-center">
              <div className="mb-8 flex justify-center">
                <TensorLogo size={120} animate />
              </div>
              <div className="text-sm text-gray-500 space-y-2">
                <p><strong>Finance</strong> + <strong>Tensor</strong></p>
                <p>= <strong className="text-black text-lg">Fynsor</strong></p>
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* Institutional Standards Section */}
      <Section className="bg-white">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl font-bold text-black mb-12 text-center font-inter">
            Institutional Standards
          </h2>
          <div className="grid md:grid-cols-2 gap-12">
            <div className="space-y-8">
              <div>
                <h3 className="text-xl font-semibold text-black mb-4 font-inter">
                  Rigorous Methodology
                </h3>
                <p className="text-gray-700 leading-relaxed">
                  Our analytical frameworks are built on proven mathematical principles
                  and validated through extensive backtesting across diverse market conditions
                  and property types.
                </p>
              </div>
              <div>
                <h3 className="text-xl font-semibold text-black mb-4 font-inter">
                  Transparency & Auditability
                </h3>
                <p className="text-gray-700 leading-relaxed">
                  Every calculation, assumption, and output is fully documented and traceable,
                  meeting the highest standards for institutional investment committee review
                  and regulatory compliance.
                </p>
              </div>
            </div>
            <div className="space-y-8">
              <div>
                <h3 className="text-xl font-semibold text-black mb-4 font-inter">
                  Enterprise Security
                </h3>
                <p className="text-gray-700 leading-relaxed">
                  Bank-grade security protocols protect sensitive financial data and proprietary
                  investment strategies, with comprehensive access controls and audit trails.
                </p>
              </div>
              <div>
                <h3 className="text-xl font-semibold text-black mb-4 font-inter">
                  Scalable Infrastructure
                </h3>
                <p className="text-gray-700 leading-relaxed">
                  Built to handle complex portfolio analysis across thousands of properties
                  while maintaining real-time performance for critical investment decisions.
                </p>
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* Mission Section */}
      <Section className="bg-gray-50">
        <div className="text-center max-w-3xl mx-auto">
          <h2 className="text-3xl font-bold text-black mb-8 font-inter">
            Our Mission
          </h2>
          <p className="text-lg text-gray-700 leading-relaxed mb-8">
            To democratize access to institutional-grade commercial real estate analysis
            by combining deep financial expertise with advanced computational intelligence,
            enabling more informed and confident investment decisions across all market segments.
          </p>
          <div className="flex justify-center">
            <div className="grid grid-cols-3 gap-4">
              {Array.from({ length: 9 }).map((_, i) => (
                <div key={i} className="w-4 h-4 border border-gray-400"></div>
              ))}
            </div>
          </div>
        </div>
      </Section>
    </Layout>
  );
};

export default AboutPage;