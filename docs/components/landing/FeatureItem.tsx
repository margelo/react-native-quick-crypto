import Image from 'next/image';
import { basePath } from '@/lib/basePath';

type FeatureItemProps = {
  title: string;
  description: React.ReactNode;
  imageSource: string;
};

export function FeatureItem({
  title,
  description,
  imageSource,
}: FeatureItemProps) {
  return (
    <div className="flex flex-col items-center text-center p-6">
      <div className="mb-6 relative w-24 h-24 sm:w-32 sm:h-32">
        <Image
          src={`${basePath}${imageSource}`}
          alt={title}
          fill
          className="object-contain drop-shadow-md"
        />
      </div>
      <h3 className="font-heading text-2xl font-bold mb-4 text-primary dark:text-white">
        {title}
      </h3>
      <p className="feature-description leading-relaxed max-w-sm text-lg">
        {description}
      </p>
    </div>
  );
}
