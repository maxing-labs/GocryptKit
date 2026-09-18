// Generates the macOS AppIcon asset catalog from Art/folder-key-10303679.png glyph.
//
// The glyph itself is monochrome black with transparency; it is treated as a mask (sourceIn filled with white)
// composited onto a custom squircle gradient background. Follows Apple's macOS icon template:
// centered 824x824 squircle within a 1024x1024 canvas, corner radius 185.
//
// Usage: swift Scripts/make-appicon.swift [palette] [--preview out.png]
//   palette: blue (default) | indigo | teal | graphite
import AppKit

let args = CommandLine.arguments
let palette = args.count > 1 && !args[1].hasPrefix("--") ? args[1] : "blue"
let previewPath: String? = args.firstIndex(of: "--preview").flatMap { i in
    i + 1 < args.count ? args[i + 1] : nil
}

let repoRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let glyphURL = repoRoot.appendingPathComponent("Art/folder-key-10303679.png")
guard let glyphImage = NSImage(contentsOf: glyphURL),
      let glyph = glyphImage.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
    fputs("Could not find or read \(glyphURL.path)\n", stderr)
    exit(1)
}

func rgb(_ r: Int, _ g: Int, _ b: Int) -> CGColor {
    NSColor(srgbRed: CGFloat(r)/255, green: CGFloat(g)/255, blue: CGFloat(b)/255, alpha: 1).cgColor
}

/// Top-to-bottom gradient colors plus glyph tint.
let palettes: [String: (top: CGColor, bottom: CGColor, glyph: CGColor)] = [
    "blue":     (rgb(74, 158, 255), rgb(10,  70, 190), .white),
    "indigo":   (rgb(124, 116, 255), rgb(46,  30, 150), .white),
    "teal":     (rgb(58, 200, 190), rgb(10,  95, 120), .white),
    "graphite": (rgb(104, 112, 128), rgb(32,  36,  48), rgb(255, 205, 90)),
]
guard let colors = palettes[palette] else {
    fputs("Unknown palette \(palette), available: \(palettes.keys.sorted().joined(separator: ", "))\n", stderr)
    exit(1)
}

/// Renders an icon with side length in pixels.
func renderIcon(px: Int) -> NSBitmapImageRep {
    let S = CGFloat(px)
    func u(_ v: CGFloat) -> CGFloat { v / 1024 * S }   // Based on 1024 template

    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    let gctx = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.current = gctx
    let ctx = gctx.cgContext
    ctx.interpolationQuality = .high

    // Apple macOS template: 824/1024 squircle, leaving 100 pt transparent margin on each side for system shadow.
    let art = CGRect(x: u(100), y: u(100), width: u(824), height: u(824))
    let radius = u(185)

    // Background: render shadow first, then draw gradient within clipped path.
    let shape = CGPath(roundedRect: art, cornerWidth: radius, cornerHeight: radius, transform: nil)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -u(10)),
                  blur: u(24),
                  color: NSColor.black.withAlphaComponent(0.28).cgColor)
    ctx.setFillColor(colors.bottom)
    ctx.addPath(shape)
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()
    let grad = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(),
                          colors: [colors.top, colors.bottom] as CFArray,
                          locations: [0, 1])!
    ctx.drawLinearGradient(grad,
                           start: CGPoint(x: art.midX, y: art.maxY),
                           end: CGPoint(x: art.midX, y: art.minY),
                           options: [])
    // Subtle specular highlight at top to avoid flat look at larger dimensions.
    let sheen = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(),
                           colors: [NSColor.white.withAlphaComponent(0.20).cgColor,
                                    NSColor.white.withAlphaComponent(0.0).cgColor] as CFArray,
                           locations: [0, 1])!
    ctx.drawLinearGradient(sheen,
                           start: CGPoint(x: art.midX, y: art.maxY),
                           end: CGPoint(x: art.midX, y: art.midY),
                           options: [])
    ctx.restoreGState()

    // Glyph: used as mask, filled with specified color via sourceIn, centered slightly above canvas midpoint.
    let glyphSide = u(500)
    let glyphRect = CGRect(x: art.midX - glyphSide / 2,
                           y: art.midY - glyphSide / 2,
                           width: glyphSide, height: glyphSide)
    ctx.saveGState()
    ctx.beginTransparencyLayer(auxiliaryInfo: nil)
    ctx.draw(glyph, in: glyphRect)
    ctx.setBlendMode(.sourceIn)
    ctx.setFillColor(colors.glyph)
    ctx.fill(glyphRect)
    ctx.endTransparencyLayer()
    ctx.restoreGState()

    NSGraphicsContext.restoreGraphicsState()
    return rep
}

func write(_ rep: NSBitmapImageRep, to url: URL) throws {
    guard let png = rep.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "makeappicon", code: 1)
    }
    try png.write(to: url)
}

// MARK: - Output Asset Catalog
let outDir = repoRoot.appendingPathComponent("App/Assets.xcassets/AppIcon.appiconset")
try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

/// (pt size, scale) — Ten standard macOS icon set entries.
let entries: [(pt: Int, scale: Int)] = [
    (16, 1), (16, 2), (32, 1), (32, 2), (128, 1),
    (128, 2), (256, 1), (256, 2), (512, 1), (512, 2),
]

var images: [[String: String]] = []
var cache: [Int: NSBitmapImageRep] = [:]
for e in entries {
    let px = e.pt * e.scale
    let rep = cache[px] ?? {
        let r = renderIcon(px: px); cache[px] = r; return r
    }()
    let filename = "icon_\(e.pt)x\(e.pt)\(e.scale == 2 ? "@2x" : "").png"
    try write(rep, to: outDir.appendingPathComponent(filename))
    images.append([
        "idiom": "mac",
        "size": "\(e.pt)x\(e.pt)",
        "scale": "\(e.scale)x",
        "filename": filename,
    ])
}

let contents: [String: Any] = [
    "images": images,
    "info": ["author": "xcode", "version": 1],
]
let json = try JSONSerialization.data(withJSONObject: contents,
                                      options: [.prettyPrinted, .sortedKeys])
try json.write(to: outDir.appendingPathComponent("Contents.json"))

if let previewPath {
    try write(renderIcon(px: 512), to: URL(fileURLWithPath: previewPath))
    print("Preview: \(previewPath)")
}
print("Palette \(palette) → \(outDir.path) (\(entries.count) entries)")
