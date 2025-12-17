import { FeatureItem } from './FeatureItem';

const FeatureList = [
    {
        title: 'Blazing Fast',
        imageSource: '/static/img/lightning-bolt.png',
        description: (
            <>
                Powered by <b>C++ JSI</b> bindings for raw native performance.
                Executes directly on the native thread, completely bypassing the bridge.
            </>
        ),
    },
    {
        title: 'Node.js Compatible',
        imageSource: '/static/img/dna.png',
        description: (
            <>
                A drop-in replacement for the Node.js <b>crypto</b> module.
                No complex setup—just install, import, and it works.
            </>
        ),
    },
    {
        title: 'Secure & Standard',
        imageSource: '/static/img/spring.png',
        description: (
            <>
                Implements over <b>60%</b> of the standard Node.js API.
                Rigorously tested against official cryptographic vectors for absolute correctness.
            </>
        ),
    },
];

export function FeatureSection() {
    return (
        <section className="py-24 bg-fd-background border-t border-fd-border/50">
            <div className="container mx-auto px-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-12">
                    {FeatureList.map((props, idx) => (
                        <FeatureItem key={idx} {...props} />
                    ))}
                </div>
            </div>
        </section>
    );
}
