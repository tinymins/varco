#!/usr/bin/env swift
// Draws the app icons in assets/icon/ from site/favicon.svg. Needs macOS.
// The outputs are committed, so only rerun this when the logo changes.
// Usage: swift scripts/make-icons.swift
import AppKit

let source = NSImage(contentsOf: URL(fileURLWithPath: "site/favicon.svg"))!
let output = URL(fileURLWithPath: "assets/icon")
let files = FileManager.default
try files.createDirectory(at: output, withIntermediateDirectories: true)

/// `inset` is the empty margin, as a share of the canvas.
func render(_ size: Int, inset: CGFloat = 0) -> NSBitmapImageRep {
    let image = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8,
        samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
        bytesPerRow: size * 4, bitsPerPixel: 32)!
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: image)
    NSGraphicsContext.current!.imageInterpolation = .high
    let margin = CGFloat(size) * inset
    source.draw(in: NSRect(x: 0, y: 0, width: CGFloat(size), height: CGFloat(size))
        .insetBy(dx: margin, dy: margin))
    NSGraphicsContext.current = nil
    return image
}

func png(_ image: NSBitmapImageRep) -> Data {
    image.representation(using: .png, properties: [:])!
}

/// An uncompressed icon image: what every Windows version reads at small sizes.
func dib(_ image: NSBitmapImageRep) -> Data {
    let size = image.pixelsWide
    var data = Data()
    func put32(_ value: UInt32) { withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) } }
    func put16(_ value: UInt16) { withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) } }
    put32(40); put32(UInt32(size)); put32(UInt32(size * 2)) // twice the height: colour, then mask
    put16(1); put16(32)
    for _ in 0..<6 { put32(0) }
    let pixels = image.bitmapData!
    for y in (0..<size).reversed() {
        for x in 0..<size {
            let p = pixels + (y * size + x) * 4
            let alpha = Int(p[3])
            // AppKit premultiplies; icon files do not.
            func straight(_ c: UInt8) -> UInt8 { alpha == 0 ? 0 : UInt8(min(255, Int(c) * 255 / alpha)) }
            data.append(contentsOf: [straight(p[2]), straight(p[1]), straight(p[0]), p[3]])
        }
    }
    // Alpha decides what shows, so the mask stays empty. Its rows pad to four bytes.
    data.append(Data(count: ((size + 31) / 32) * 4 * size))
    return data
}

// macOS: Apple's grid leaves 100 of every 1024 pixels empty on each side.
let iconset = files.temporaryDirectory.appendingPathComponent("varco-\(UUID().uuidString).iconset")
try files.createDirectory(at: iconset, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = scale == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
        try png(render(base * scale, inset: 100.0 / 1024)).write(to: iconset.appendingPathComponent(name))
    }
}
let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", output.appendingPathComponent("varco.icns").path]
try iconutil.run()
iconutil.waitUntilExit()
precondition(iconutil.terminationStatus == 0, "iconutil failed")
try files.removeItem(at: iconset)

// Windows: small sizes as plain images, the largest as PNG, as is conventional.
let entries: [(size: Int, data: Data)] = [16, 24, 32, 48, 256].map { size in
    let image = render(size)
    return (size, size == 256 ? png(image) : dib(image))
}
var ico = Data([0, 0, 1, 0, UInt8(entries.count), 0])
var offset = 6 + 16 * entries.count
for entry in entries {
    let side = UInt8(entry.size == 256 ? 0 : entry.size) // 0 means 256
    ico.append(contentsOf: [side, side, 0, 0, 1, 0, 32, 0])
    withUnsafeBytes(of: UInt32(entry.data.count).littleEndian) { ico.append(contentsOf: $0) }
    withUnsafeBytes(of: UInt32(offset).littleEndian) { ico.append(contentsOf: $0) }
    offset += entry.data.count
}
for entry in entries { ico.append(entry.data) }
try ico.write(to: output.appendingPathComponent("varco.ico"))

// The window's own icon, for Windows and Linux title bars and task bars.
try png(render(256)).write(to: output.appendingPathComponent("varco.png"))
