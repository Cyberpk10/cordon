import Nav from "@/components/Nav";
import Hero from "@/components/Hero";
import FrameworkBar from "@/components/FrameworkBar";
import VideoDemo from "@/components/VideoDemo";
import EmailPlayground from "@/components/EmailPlayground";
import StatStrip from "@/components/StatStrip";
import PlatformCards from "@/components/PlatformCards";
import EarlyWarning from "@/components/EarlyWarning";
import PhishingSimulation from "@/components/PhishingSimulation";
import Investigation from "@/components/Investigation";
import ProductTour from "@/components/ProductTour";
import WhyAegis from "@/components/WhyAegis";
import AutonomyBand from "@/components/AutonomyBand";
import AboutFounder from "@/components/AboutFounder";
import FinalCta from "@/components/FinalCta";
import Footer from "@/components/Footer";
import { getScreenshotAvailability } from "@/lib/screenshots";

export default function Home() {
  const screenshots = getScreenshotAvailability();

  return (
    <>
      <Nav />
      <main className="flex-1">
        <Hero />
        <FrameworkBar />
        <VideoDemo hasWalkthroughVideo={screenshots.walkthroughVideo} />
        <EmailPlayground />
        <StatStrip />
        <PlatformCards />
        <EarlyWarning />
        <PhishingSimulation />
        <Investigation />
        <ProductTour
          hasAnalyzeMalicious={screenshots.analyzeMalicious}
          hasDashboard={screenshots.dashboard}
        />
        <WhyAegis />
        <AutonomyBand />
        <AboutFounder />
        <FinalCta />
      </main>
      <Footer />
    </>
  );
}
