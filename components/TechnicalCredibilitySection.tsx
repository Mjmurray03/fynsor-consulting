'use client';

import { useEffect, useRef, useState } from 'react';

export default function TechnicalCredibilitySection() {
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
    <section id="technical" ref={sectionRef} className="section-padding relative">
      <div className="container mx-auto px-4">
        <div className={`text-center mb-16 transition-all duration-1000 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
          <h2 className="text-5xl md:text-6xl font-bold mb-6">
            <span className="gradient-text">Tensor-Level Engineering</span>
          </h2>
          <p className="text-xl text-gray-400 max-w-4xl mx-auto">
            We work at the tensor level - the fundamental mathematical structures that power neural networks.
            By understanding AI at its mathematical core, we can build deterministic systems with predictable outcomes.
          </p>
        </div>

        <div className={`grid grid-cols-1 lg:grid-cols-2 gap-16 items-center transition-all duration-1000 delay-300 ${isVisible ? 'opacity-100' : 'opacity-0'}`}>
          <div className="space-y-8">
            <div className="glass p-6">
              <h3 className="text-xl font-semibold text-white mb-4">Optimize Tensor Operations</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                Direct manipulation of tensor computations for specific mathematical operations,
                eliminating unnecessary computational overhead.
              </p>
            </div>

            <div className="glass p-6">
              <h3 className="text-xl font-semibold text-white mb-4">Design Focused Architectures</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                Neural network architectures engineered to excel at single tasks rather than
                general-purpose approximations.
              </p>
            </div>

            <div className="glass p-6">
              <h3 className="text-xl font-semibold text-white mb-4">Allocate Finite Resources</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                Precise resource allocation for maximum impact within defined computational boundaries
                and memory constraints.
              </p>
            </div>

            <div className="glass p-6">
              <h3 className="text-xl font-semibold text-white mb-4">Build Deterministic Systems</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                Production-ready systems with predictable outputs and measurable performance
                characteristics.
              </p>
            </div>
          </div>

          <div className="glass p-8">
            <div className="text-center mb-8">
              <div className="text-6xl font-mono text-blue-400 mb-4">
                T<sub className="text-2xl">ij</sub>
              </div>
              <div className="text-sm text-gray-500 uppercase tracking-wide mb-6">Tensor Mathematics</div>
            </div>

            <div className="space-y-4 text-sm">
              <div className="bg-gray-900 p-4 font-mono text-green-400">
                <div className="text-xs text-gray-500 mb-2"># Bounded computation</div>
                <div>∀ x ∈ [a,b] : f(x) → y ∈ [c,d]</div>
              </div>

              <div className="bg-gray-900 p-4 font-mono text-blue-400">
                <div className="text-xs text-gray-500 mb-2"># Finite dimensionality</div>
                <div>dim(V) = n &lt; ∞</div>
              </div>

              <div className="bg-gray-900 p-4 font-mono text-purple-400">
                <div className="text-xs text-gray-500 mb-2"># Deterministic output</div>
                <div>f: X → Y, |Y| finite</div>
              </div>
            </div>

            <div className="mt-6 text-center">
              <div className="text-xs text-gray-500">
                Our approach transforms the theoretically infinite-dimensional nature of tensors
                into practically finite, production-ready systems.
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}