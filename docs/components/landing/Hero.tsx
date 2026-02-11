import Link from 'next/link';

export function Hero() {
    return (
        <div className="relative overflow-hidden bg-[#89CFF0] dark:bg-[#161E31] py-24 sm:py-32 transition-colors duration-300">
            {/* Use a specific blue hex to match the 'sky blue' of the provided screenshot, or use a gradient if preferred. 
           User asked for 'depth copy', the image has a solid sky/light blue background. 
           #89CFF0 is 'Baby Blue'. Let's try to match the image closely. 
       */}
            <div className="container mx-auto px-4 text-center z-10 relative">
                <div className="mb-8 flex justify-center">
                    {/* Placeholder for a logo if we had one, sticking to text for now or maybe a generic icon */}
                    <div className="text-6xl mb-4">
                        🔋
                    </div>
                </div>

                <h1 className="hero-title text-6xl sm:text-7xl md:text-8xl mb-6 tracking-wide">
                    Quick Crypto
                </h1>

                <p className="mx-auto mt-6 max-w-2xl text-xl leading-8 mb-10 font-medium text-[#232a3f] dark:text-[#ffffff]">
                    The fastest, Next-generation cryptography library for React Native.<br />
                    Full Node.js API compatibility.
                </p>

                <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-6">
                    <Link
                        href="/docs/introduction/quick-start"
                        className="hero-button"
                    >
                        Get Started
                    </Link>
                    <Link
                        href="/docs/guides/migration"
                        className="text-sm font-semibold leading-6 text-gray-900 dark:text-white"
                    >
                        Migrate from legacy <span aria-hidden="true">→</span>
                    </Link>
                </div>
            </div>
        </div>
    );
}
