import sharp from 'sharp';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import pngToIco from 'png-to-ico';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const iconsDir = path.join(__dirname, '..', 'src-tauri', 'icons');

// Create icons directory
if (!fs.existsSync(iconsDir)) {
    fs.mkdirSync(iconsDir, { recursive: true });
}

// Create a cyberpunk shield icon programmatically
async function createIcon() {
    const size = 1024;
    
    // Create an SVG shield with cyberpunk styling
    const svg = `
    <svg width="${size}" height="${size}" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:#0a0f1a;stop-opacity:1" />
                <stop offset="100%" style="stop-color:#1a1f2e;stop-opacity:1" />
            </linearGradient>
            <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:#00f5d4;stop-opacity:1" />
                <stop offset="100%" style="stop-color:#00b4d8;stop-opacity:1" />
            </linearGradient>
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="20" result="coloredBlur"/>
                <feMerge>
                    <feMergeNode in="coloredBlur"/>
                    <feMergeNode in="SourceGraphic"/>
                </feMerge>
            </filter>
        </defs>
        
        <!-- Background circle -->
        <circle cx="${size/2}" cy="${size/2}" r="${size/2 - 20}" fill="url(#bgGrad)" />
        
        <!-- Shield shape -->
        <path 
            d="M ${size/2} ${size * 0.15}
               L ${size * 0.8} ${size * 0.28}
               L ${size * 0.8} ${size * 0.55}
               Q ${size * 0.8} ${size * 0.75} ${size/2} ${size * 0.88}
               Q ${size * 0.2} ${size * 0.75} ${size * 0.2} ${size * 0.55}
               L ${size * 0.2} ${size * 0.28}
               Z"
            fill="none"
            stroke="url(#shieldGrad)"
            stroke-width="40"
            filter="url(#glow)"
        />
        
        <!-- Inner shield glow -->
        <path 
            d="M ${size/2} ${size * 0.22}
               L ${size * 0.72} ${size * 0.32}
               L ${size * 0.72} ${size * 0.53}
               Q ${size * 0.72} ${size * 0.68} ${size/2} ${size * 0.78}
               Q ${size * 0.28} ${size * 0.68} ${size * 0.28} ${size * 0.53}
               L ${size * 0.28} ${size * 0.32}
               Z"
            fill="rgba(0, 245, 212, 0.1)"
            stroke="url(#shieldGrad)"
            stroke-width="3"
        />
        
        <!-- Checkmark -->
        <path 
            d="M ${size * 0.35} ${size * 0.5}
               L ${size * 0.45} ${size * 0.62}
               L ${size * 0.65} ${size * 0.38}"
            fill="none"
            stroke="#00f5d4"
            stroke-width="45"
            stroke-linecap="round"
            stroke-linejoin="round"
            filter="url(#glow)"
        />
    </svg>`;
    
    // Generate base icon
    const baseIcon = await sharp(Buffer.from(svg))
        .png()
        .toBuffer();
    
    // Save as app-icon.png for tauri icon command
    await sharp(baseIcon)
        .resize(1024, 1024)
        .png()
        .toFile(path.join(__dirname, '..', 'app-icon.png'));
    
    console.log('Created app-icon.png');
    
    // Generate various sizes
    const sizes = [32, 128, 256, 512];
    
    for (const s of sizes) {
        await sharp(baseIcon)
            .resize(s, s)
            .png()
            .toFile(path.join(iconsDir, `${s}x${s}.png`));
        console.log(`Created ${s}x${s}.png`);
    }
    
    // Create icon.png (512x512 for macOS)
    await sharp(baseIcon)
        .resize(512, 512)
        .png()
        .toFile(path.join(iconsDir, 'icon.png'));
    console.log('Created icon.png');
    
    // Create icon.ico using png-to-ico for proper ICO format
    const ico256Path = path.join(iconsDir, '256x256.png');
    const icoBuffer = await pngToIco([ico256Path]);
    fs.writeFileSync(path.join(iconsDir, 'icon.ico'), icoBuffer);
    console.log('Created icon.ico (proper ICO format)');
    
    // Create Square icons for Windows
    await sharp(baseIcon)
        .resize(30, 30)
        .png()
        .toFile(path.join(iconsDir, 'Square30x30Logo.png'));
    
    await sharp(baseIcon)
        .resize(44, 44)
        .png()
        .toFile(path.join(iconsDir, 'Square44x44Logo.png'));
    
    await sharp(baseIcon)
        .resize(71, 71)
        .png()
        .toFile(path.join(iconsDir, 'Square71x71Logo.png'));
    
    await sharp(baseIcon)
        .resize(89, 89)
        .png()
        .toFile(path.join(iconsDir, 'Square89x89Logo.png'));
    
    await sharp(baseIcon)
        .resize(107, 107)
        .png()
        .toFile(path.join(iconsDir, 'Square107x107Logo.png'));
    
    await sharp(baseIcon)
        .resize(142, 142)
        .png()
        .toFile(path.join(iconsDir, 'Square142x142Logo.png'));
    
    await sharp(baseIcon)
        .resize(150, 150)
        .png()
        .toFile(path.join(iconsDir, 'Square150x150Logo.png'));
    
    await sharp(baseIcon)
        .resize(284, 284)
        .png()
        .toFile(path.join(iconsDir, 'Square284x284Logo.png'));
    
    await sharp(baseIcon)
        .resize(310, 310)
        .png()
        .toFile(path.join(iconsDir, 'Square310x310Logo.png'));
    
    // StoreLogo
    await sharp(baseIcon)
        .resize(50, 50)
        .png()
        .toFile(path.join(iconsDir, 'StoreLogo.png'));
    
    console.log('Created all Windows Square logos');
    console.log('\nAll icons generated successfully! 🎉');
}

createIcon().catch(console.error);

