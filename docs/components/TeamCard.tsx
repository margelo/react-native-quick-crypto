import { Github, Twitter, Globe, Linkedin } from 'lucide-react';

interface SocialLink {
    icon: 'github' | 'twitter' | 'web' | 'linkedin';
    url: string;
}

interface TeamMemberProps {
    name: string;
    role: string;
    avatarUrl: string;
    bio?: string;
    socials?: SocialLink[];
    isOrg?: boolean;
}

export function TeamCard({ name, role, avatarUrl, bio, socials, isOrg }: TeamMemberProps) {
    const IconMap = {
        github: Github,
        twitter: Twitter,
        web: Globe,
        linkedin: Linkedin
    };

    const links = socials && socials.length > 0 && (
        <div className="flex gap-2">
            {socials.map((social) => {
                const Icon = IconMap[social.icon];
                return (
                    <a
                        key={social.icon}
                        href={social.url}
                        target="_blank"
                        className="text-fd-muted-foreground hover:text-fd-foreground transition-colors"
                    >
                        <Icon className="w-3.5 h-3.5" />
                    </a>
                );
            })}
        </div>
    );

    return (
        <div className="flex items-center gap-3 p-3 bg-fd-card border border-fd-border rounded-lg transition-all hover:border-fd-primary/50 group">
            <img
                src={avatarUrl}
                alt={name}
                className={`w-10 h-10 object-cover ${isOrg ? 'rounded-md' : 'rounded-full border border-fd-border/50'}`}
            />

            <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-0.5">
                    <h3 className="text-sm font-bold text-fd-foreground truncate pr-2">
                        {name}
                    </h3>
                    {links}
                </div>
                <div className="text-[10px] font-semibold text-fd-primary uppercase tracking-widest opacity-80">
                    {role}
                </div>
            </div>
        </div>
    );
}
