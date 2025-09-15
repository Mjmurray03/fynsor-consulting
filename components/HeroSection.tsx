'use client';

import { useEffect, useState } from 'react';
import Image from 'next/image';

export default function HeroSection() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <section id="hero" className="relative min-h-screen flex items-center justify-center overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[#0A0A0A] to-[#0A0A0A] opacity-50" />

      <div className="relative z-10 text-center px-4 max-w-6xl mx-auto">
        <div className={`mb-12 transition-all duration-1000 ${mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
          <div className="relative w-32 h-32 mx-auto mb-8">
            <Image
              src="/images/logo.png"
              alt="Fynsor Logo"
              fill
              className="object-contain animate-pulse"
              priority
            />
          </div>
        </div>

        <h1 className={`text-7xl md:text-8xl font-bold mb-6 transition-all duration-1000 delay-200 ${mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
          <span className="gradient-text">FYNSOR</span>
        </h1>

        <p className={`text-2xl md:text-3xl text-gray-300 mb-8 transition-all duration-1000 delay-400 ${mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
          Infinite AI. Finite Focus.
        </p>

        <div className={`max-w-3xl mx-auto text-center transition-all duration-1000 delay-600 ${mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
          <p className="text-xl text-gray-400 leading-relaxed">
            Precision-engineered AI systems that do one thing exceptionally well.
          </p>
        </div>

        <div className={`flex flex-col items-center transition-all duration-1000 delay-800 ${mounted ? 'opacity-100' : 'opacity-0'}`}>
          <div className="animate-bounce mt-8">
            <svg
              className="w-6 h-6 text-gray-400"
              fill="none"
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path d="M19 14l-7 7m0 0l-7-7m7 7V3"></path>
            </svg>
          </div>
        </div>
      </div>

      <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-gray-800 to-transparent" />
    </section>
  );
}