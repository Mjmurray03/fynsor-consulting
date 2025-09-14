'use client';

import React, { useState, useEffect } from 'react';
import Layout from '../../components/layout/Layout';
import Section from '../../components/ui/Section';
import TensorLogo from '../../components/animations/TensorLogo';
import { trackContactFormSubmission, trackFormEngagement, trackButtonClick } from '@/lib/gtag';

const ContactPage: React.FC = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    company: '',
    phone: '',
    propertyType: '',
    investmentSize: '',
    message: '',
    honeypot: ''
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Honeypot check
    if (formData.honeypot) {
      return; // Bot detected, silently reject
    }

    setIsSubmitting(true);
    setSubmitStatus('idle');
    setErrorMessage('');

    try {
      const response = await fetch('/api/contact', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: formData.name,
          email: formData.email,
          company: formData.company,
          phone: formData.phone,
          property_type: formData.propertyType,
          investment_size: formData.investmentSize,
          message: formData.message
        })
      });

      if (response.ok) {
        setSubmitStatus('success');

        // Track successful form submission with Google Analytics
        trackContactFormSubmission({
          name: formData.name,
          email: formData.email,
          company: formData.company,
          phone: formData.phone,
          property_type: formData.propertyType,
          investment_size: formData.investmentSize,
          message: formData.message
        });

        setFormData({
          name: '',
          email: '',
          company: '',
          phone: '',
          propertyType: '',
          investmentSize: '',
          message: '',
          honeypot: ''
        });
      } else {
        const errorData = await response.json();
        setSubmitStatus('error');
        setErrorMessage(errorData.message || 'Submission failed. Please try again.');
      }
    } catch (error) {
      setSubmitStatus('error');
      setErrorMessage('Network error. Please check your connection and try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleFieldFocus = (fieldName: string) => {
    // Track form engagement when user starts interacting
    trackFormEngagement(fieldName);
  };

  const handleSubmitClick = () => {
    // Track submit button click
    trackButtonClick('contact_form_submit', '/contact');
  };

  return (
    <Layout>
      {/* Header Section */}
      <Section className="bg-white">
        <div className="text-center max-w-4xl mx-auto">
          <div className="flex justify-center mb-8">
            <TensorLogo size={80} />
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-black mb-6 font-inter">
            Contact
          </h1>
          <p className="text-xl text-gray-600 leading-relaxed">
            Connect with our team to discuss your commercial real estate
            analysis needs and discover how Fynsor can enhance your investment decisions.
          </p>
        </div>
      </Section>

      {/* Contact Form Section */}
      <Section className="bg-gray-50">
        <div className="max-w-6xl mx-auto">
          <div className="grid lg:grid-cols-2 gap-16 items-start">
            {/* Contact Form */}
            <div className="bg-white border border-gray-200 p-8">
              <h2 className="text-2xl font-semibold text-black mb-6 font-inter">
                Get Started
              </h2>
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Honeypot field (hidden) */}
                <input
                  type="text"
                  name="honeypot"
                  value={formData.honeypot}
                  onChange={handleChange}
                  style={{ display: 'none' }}
                  tabIndex={-1}
                  autoComplete="off"
                />

                <div>
                  <label htmlFor="name" className="block text-sm font-medium text-black mb-2">
                    Name *
                  </label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    required
                    value={formData.name}
                    onChange={handleChange}
                    onFocus={() => handleFieldFocus('name')}
                    className="w-full px-3 py-2 border border-gray-300 focus:border-black focus:outline-none transition-colors duration-200"
                    placeholder="Your full name"
                  />
                </div>

                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-black mb-2">
                    Email *
                  </label>
                  <input
                    type="email"
                    id="email"
                    name="email"
                    required
                    value={formData.email}
                    onChange={handleChange}
                    className="w-full px-3 py-2 border border-gray-300 focus:border-black focus:outline-none transition-colors duration-200"
                    placeholder="your.email@company.com"
                  />
                </div>

                <div>
                  <label htmlFor="company" className="block text-sm font-medium text-black mb-2">
                    Company
                  </label>
                  <input
                    type="text"
                    id="company"
                    name="company"
                    value={formData.company}
                    onChange={handleChange}
                    className="w-full px-3 py-2 border border-gray-300 focus:border-black focus:outline-none transition-colors duration-200"
                    placeholder="Your organization"
                  />
                </div>

                <div>
                  <label htmlFor="phone" className="block text-sm font-medium text-black mb-2">
                    Phone
                  </label>
                  <input
                    type="tel"
                    id="phone"
                    name="phone"
                    value={formData.phone}
                    onChange={handleChange}
                    className="w-full px-3 py-2 border border-gray-300 focus:border-black focus:outline-none transition-colors duration-200"
                    placeholder="+1 (555) 123-4567"
                  />
                </div>

                <div>
                  <label htmlFor="propertyType" className="block text-sm font-medium text-black mb-2">
                    Property Type
                  </label>
                  <select
                    id="propertyType"
                    name="propertyType"
                    value={formData.propertyType}
                    onChange={handleChange}
                    className="w-full px-3 py-2 border border-gray-300 focus:border-black focus:outline-none transition-colors duration-200"
                  >
                    <option value="">Select property type</option>
                    <option value="office">Office</option>
                    <option value="retail">Retail</option>
                    <option value="industrial">Industrial</option>
                    <option value="multifamily">Multifamily</option>
                    <option value="hospitality">Hospitality</option>
                    <option value="healthcare">Healthcare</option>
                    <option value="mixed-use">Mixed Use</option>
                    <option value="other">Other</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="investmentSize" className="block text-sm font-medium text-black mb-2">
                    Investment Size
                  </label>
                  <select
                    id="investmentSize"
                    name="investmentSize"
                    value={formData.investmentSize}
                    onChange={handleChange}
                    className="w-full px-3 py-2 border border-gray-300 focus:border-black focus:outline-none transition-colors duration-200"
                  >
                    <option value="">Select investment range</option>
                    <option value="under-1m">Under $1M</option>
                    <option value="1m-5m">$1M - $5M</option>
                    <option value="5m-10m">$5M - $10M</option>
                    <option value="10m-25m">$10M - $25M</option>
                    <option value="25m-50m">$25M - $50M</option>
                    <option value="50m-100m">$50M - $100M</option>
                    <option value="over-100m">Over $100M</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="message" className="block text-sm font-medium text-black mb-2">
                    Message *
                  </label>
                  <textarea
                    id="message"
                    name="message"
                    required
                    rows={6}
                    value={formData.message}
                    onChange={handleChange}
                    className="w-full px-3 py-2 border border-gray-300 focus:border-black focus:outline-none resize-none transition-colors duration-200"
                    placeholder="Tell us about your project, timeline, and specific requirements..."
                  />
                </div>

                {/* Status Messages */}
                {submitStatus === 'success' && (
                  <div className="bg-green-50 border border-green-200 text-green-800 px-4 py-3 rounded">
                    Thank you for your message. We'll respond within 24 hours.
                  </div>
                )}

                {submitStatus === 'error' && (
                  <div className="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded">
                    {errorMessage}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isSubmitting}
                  onClick={handleSubmitClick}
                  className="w-full bg-black text-white py-3 px-6 hover:bg-gray-800 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors duration-200 font-medium"
                >
                  {isSubmitting ? 'Sending...' : 'Send Message'}
                </button>

                <p className="text-xs text-gray-500 mt-4">
                  All communications are encrypted and protected under strict confidentiality agreements.
                  Rate limited to 5 submissions per hour for security.
                </p>
              </form>

              <div className="mt-8 pt-8 border-t border-gray-200">
                <h3 className="text-lg font-semibold text-black mb-4 font-inter">
                  Direct Contact
                </h3>
                <div className="space-y-3 text-gray-700">
                  <p>
                    <strong className="text-black">Email:</strong> contact@fynsor.com
                  </p>
                  <p>
                    <strong className="text-black">Phone:</strong> +1 (555) 123-4567
                  </p>
                  <p>
                    <strong className="text-black">Response Time:</strong> Within 24 hours
                  </p>
                </div>
              </div>
            </div>

            {/* Logo and Information */}
            <div className="flex flex-col justify-center items-center text-center lg:pl-8">
              <div className="mb-12">
                <TensorLogo size={200} animate />
              </div>

              <div className="space-y-8 max-w-md">
                <div>
                  <h3 className="text-xl font-semibold text-black mb-4 font-inter">
                    Professional Consultation
                  </h3>
                  <p className="text-gray-700 leading-relaxed">
                    Our team provides expert guidance on complex commercial real estate
                    analysis challenges, helping you leverage advanced modeling techniques
                    for better investment outcomes.
                  </p>
                </div>

                <div>
                  <h3 className="text-xl font-semibold text-black mb-4 font-inter">
                    Institutional Standards
                  </h3>
                  <p className="text-gray-700 leading-relaxed">
                    Every engagement meets the highest standards for institutional
                    investment analysis, with comprehensive documentation and
                    audit-ready methodologies.
                  </p>
                </div>

                <div>
                  <h3 className="text-xl font-semibold text-black mb-4 font-inter">
                    Confidentiality Assured
                  </h3>
                  <p className="text-gray-700 leading-relaxed">
                    All communications and project details are protected under
                    strict confidentiality agreements and enterprise-grade security protocols.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* Additional Information */}
      <Section className="bg-white">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl font-bold text-black mb-8 font-inter">
            How We Can Help
          </h2>
          <div className="grid md:grid-cols-3 gap-8">
            <div>
              <div className="mb-4 flex justify-center">
                <div className="w-12 h-12 border border-gray-600 flex items-center justify-center">
                  <TensorLogo size={24} />
                </div>
              </div>
              <h3 className="text-lg font-semibold text-black mb-3 font-inter">
                Custom Analysis
              </h3>
              <p className="text-gray-700 text-sm leading-relaxed">
                Tailored financial models and market analysis for specific properties
                or portfolios, built to your exact requirements.
              </p>
            </div>

            <div>
              <div className="mb-4 flex justify-center">
                <div className="w-12 h-12 border border-gray-600 flex items-center justify-center">
                  <div className="w-6 h-6 grid grid-cols-2 gap-px">
                    <div className="bg-black"></div>
                    <div className="bg-gray-400"></div>
                    <div className="bg-gray-400"></div>
                    <div className="bg-black"></div>
                  </div>
                </div>
              </div>
              <h3 className="text-lg font-semibold text-black mb-3 font-inter">
                Platform Integration
              </h3>
              <p className="text-gray-700 text-sm leading-relaxed">
                Seamless integration with existing systems and workflows,
                enhancing your current analytical capabilities.
              </p>
            </div>

            <div>
              <div className="mb-4 flex justify-center">
                <div className="w-12 h-12 border border-gray-600 flex items-center justify-center">
                  <div className="w-6 h-6 grid grid-cols-3 gap-px">
                    {Array.from({ length: 9 }).map((_, i) => (
                      <div key={i} className="bg-gray-400"></div>
                    ))}
                  </div>
                </div>
              </div>
              <h3 className="text-lg font-semibold text-black mb-3 font-inter">
                Training & Support
              </h3>
              <p className="text-gray-700 text-sm leading-relaxed">
                Comprehensive training programs and ongoing support to maximize
                the value of advanced analytical tools and methodologies.
              </p>
            </div>
          </div>
        </div>
      </Section>
    </Layout>
  );
};

export default ContactPage;