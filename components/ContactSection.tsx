'use client';

import { useState, FormEvent } from 'react';

export default function ContactSection() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    company: '',
    message: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState<'idle' | 'success' | 'error'>('idle');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSubmitStatus('idle');

    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      setSubmitStatus('success');
      setFormData({ name: '', email: '', company: '', message: '' });
      setTimeout(() => setSubmitStatus('idle'), 5000);
    } catch (error) {
      setSubmitStatus('error');
      setTimeout(() => setSubmitStatus('idle'), 5000);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  };

  return (
    <section id="contact" className="section-padding relative">
      <div className="container mx-auto px-4 max-w-4xl">
        <div className="text-center mb-16">
          <h2 className="text-5xl md:text-6xl font-bold mb-4">
            <span className="gradient-text">Define Your Boundaries. Deploy Your Solution.</span>
          </h2>
          <p className="text-xl text-gray-400">
            Let's discuss how focused AI can transform your critical workflow.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="glass p-8 md:p-12">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-gray-400 mb-2">
                Name
              </label>
              <input
                type="text"
                id="name"
                name="name"
                value={formData.name}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 bg-transparent border border-gray-800 text-white placeholder-gray-600 focus:border-gray-600 focus:outline-none transition-colors"
                placeholder="John Doe"
              />
            </div>
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-400 mb-2">
                Email
              </label>
              <input
                type="email"
                id="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 bg-transparent border border-gray-800 text-white placeholder-gray-600 focus:border-gray-600 focus:outline-none transition-colors"
                placeholder="john@company.com"
              />
            </div>
          </div>

          <div className="mb-6">
            <label htmlFor="company" className="block text-sm font-medium text-gray-400 mb-2">
              Company
            </label>
            <input
              type="text"
              id="company"
              name="company"
              value={formData.company}
              onChange={handleChange}
              required
              className="w-full px-4 py-3 bg-transparent border border-gray-800 text-white placeholder-gray-600 focus:border-gray-600 focus:outline-none transition-colors"
              placeholder="Acme Capital Partners"
            />
          </div>

          <div className="mb-8">
            <label htmlFor="message" className="block text-sm font-medium text-gray-400 mb-2">
              Message
            </label>
            <textarea
              id="message"
              name="message"
              value={formData.message}
              onChange={handleChange}
              required
              rows={4}
              className="w-full px-4 py-3 bg-transparent border border-gray-800 text-white placeholder-gray-600 focus:border-gray-600 focus:outline-none transition-colors resize-none"
              placeholder="Describe the specific workflow you want to automate completely..."
            />
          </div>

          <div className="flex items-center justify-between">
            <button
              type="submit"
              disabled={isSubmitting}
              className={`px-8 py-3 border border-gray-800 text-white font-medium hover:bg-white hover:text-black transition-all duration-300 ${
                isSubmitting ? 'opacity-50 cursor-not-allowed' : ''
              }`}
            >
              {isSubmitting ? 'Starting Focused...' : 'Start Focused'}
            </button>

            {submitStatus === 'success' && (
              <span className="text-green-500 text-sm animate-fadeIn">Message sent successfully</span>
            )}
            {submitStatus === 'error' && (
              <span className="text-red-500 text-sm animate-fadeIn">Failed to send message</span>
            )}
          </div>
        </form>

        <div className="mt-12 text-center text-gray-500 text-sm">
          <p className="mb-2">For immediate assistance</p>
          <a href="mailto:contact@fynsor.io" className="text-gray-400 hover:text-white transition-colors">
            contact@fynsor.io
          </a>
        </div>
      </div>
    </section>
  );
}