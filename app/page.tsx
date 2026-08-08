import Nav from "@/components/Nav";
import Hero from "@/components/Hero";
import StatStrip from "@/components/StatStrip";
import PlatformCards from "@/components/PlatformCards";
import ProductTour from "@/components/ProductTour";
import WhyAegis from "@/components/WhyAegis";
import AutonomyBand from "@/components/AutonomyBand";
import FinalCta from "@/components/FinalCta";
import Footer from "@/components/Footer";

export default function Home() {
  return (
    <>
      <Nav />
      <main className="flex-1">
        <Hero />
        <StatStrip />
        <PlatformCards />
        <ProductTour />
        <WhyAegis />
        <AutonomyBand />
        <FinalCta />
      </main>
      <Footer />
    </>
  );
}
