
import { Hero } from '../../components/landing/Hero';
import { FeatureSection } from '../../components/landing/FeatureSection';

export default function HomePage() {
  return (

    <div className="flex flex-col min-h-screen bg-fd-background">
      <Hero />
      <FeatureSection />
    </div>

  );
}
