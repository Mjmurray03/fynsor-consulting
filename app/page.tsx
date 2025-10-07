import Navigation from '@/components/Navigation';
import HeroSection from '@/components/HeroSection';
import WhatWeDoSection from '@/components/WhatWeDoSection';
import WhyFocusedSection from '@/components/WhyFocusedSection';
import RecentWorkSection from '@/components/RecentWorkSection';
import MethodSection from '@/components/MethodSection';
import PhilosophySection from '@/components/PhilosophySection';
import TechnicalCredibilitySection from '@/components/TechnicalCredibilitySection';
import ContactSection from '@/components/ContactSection';
import Footer from '@/components/Footer';

export default function Home() {
  return (
    <>
      <Navigation />
      <main className="min-h-screen">
        <HeroSection />
        <WhatWeDoSection />
        <WhyFocusedSection />
        <RecentWorkSection />
        <MethodSection />
        <PhilosophySection />
        <TechnicalCredibilitySection />
        <ContactSection />
      </main>
      <Footer />
    </>
  );
}