# Draws the NSIS installer bitmaps (24-bit BMP at the sizes MUI2 expects: sidebar 164x314, header
# 150x57) in MAX's palette: the plum-ink background, the "M" sector-grid mark, and a strip of the
# Recovery Map along the bottom (green live data, blue metadata, yellow recoverable, grey unscanned).
#   powershell -File installer\make-art.ps1
param([string]$Product = "MAX", [string]$Tagline = "File Recovery`nFind, preview, restore")
Add-Type -AssemblyName System.Drawing
$here = $PSScriptRoot
$ink = [Drawing.Color]::FromArgb(28, 22, 52)
$tileC = [Drawing.Color]::FromArgb(44, 32, 92)
$dim = [Drawing.Color]::FromArgb(78, 64, 140)
$lit = [Drawing.Color]::FromArgb(190, 176, 255)
$text = [Drawing.Color]::FromArgb(236, 233, 247)
$sub = [Drawing.Color]::FromArgb(186, 178, 214)
$mapUn = [Drawing.Color]::FromArgb(62, 55, 92)
$mapLive = [Drawing.Color]::FromArgb(88, 167, 123)
$mapMeta = [Drawing.Color]::FromArgb(91, 146, 236)
$mapRec = [Drawing.Color]::FromArgb(240, 196, 69)
$mapEmpty = [Drawing.Color]::FromArgb(40, 34, 64)

function New-Font([float]$size, [Drawing.FontStyle]$style) {
  foreach ($f in "Segoe UI Variable Display", "Segoe UI Semibold", "Segoe UI") {
    try { $font = New-Object Drawing.Font($f, $size, $style, [Drawing.GraphicsUnit]::Pixel); if ($font.Name -eq $f) { return $font } } catch {}
  }
  New-Object Drawing.Font("Arial", $size, $style, [Drawing.GraphicsUnit]::Pixel)
}

function RoundRect([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
  $p = New-Object Drawing.Drawing2D.GraphicsPath
  $d = $r * 2
  $p.AddArc($x, $y, $d, $d, 180, 90); $p.AddArc(($x + $w - $d), $y, $d, $d, 270, 90)
  $p.AddArc(($x + $w - $d), ($y + $h - $d), $d, $d, 0, 90); $p.AddArc($x, ($y + $h - $d), $d, $d, 90, 90)
  $p.CloseFigure(); return $p
}

# The mark: a rounded tile with a 4x4 sector grid whose lit cells draw an "M".
function Draw-Mark($g, [float]$x, [float]$y, [float]$size) {
  $g.FillPath((New-Object Drawing.SolidBrush $tileC), (RoundRect $x $y $size $size ($size * 0.22)))
  $n = 4; $pad = $size * 0.16; $gap = $size * 0.05
  $cell = ($size - 2 * $pad - ($n - 1) * $gap) / $n
  for ($r = 0; $r -lt $n; $r++) { for ($c = 0; $c -lt $n; $c++) {
    $on = ($c -eq 0 -or $c -eq 3 -or ($r -eq $c -and $r -lt 2) -or (($r + $c) -eq 3 -and $r -lt 2))
    $b = New-Object Drawing.SolidBrush ($(if ($on) { $lit } else { $dim }))
    $g.FillPath($b, (RoundRect ($x + $pad + $c * ($cell + $gap)) ($y + $pad + $r * ($cell + $gap)) $cell $cell ($cell * 0.2)))
  } }
}

# --- Welcome / finish sidebar: 164 x 314 ---
$w = 164; $h = 314
$bmp = New-Object Drawing.Bitmap($w, $h, [Drawing.Imaging.PixelFormat]::Format24bppRgb)
$g = [Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = "AntiAlias"; $g.TextRenderingHint = "AntiAliasGridFit"
$g.Clear($ink)
# Recovery Map strip: scanned left to right, finds appear as the scan passes.
$cols = 13; $rows = 7; $pitch = 11; $cell = 8.5
$x0 = ($w - ($cols * $pitch - ($pitch - $cell))) / 2; $y0 = $h - 18 - $rows * $pitch
$rand = New-Object Random 11
for ($i = 0; $i -lt $cols * $rows; $i++) {
  $c = $i % $cols; $r = [Math]::Floor($i / $cols)
  $v = $rand.NextDouble()
  $color = if ($i -gt 70) { $mapUn } elseif ($i -lt 6) { $mapMeta } elseif ($v -lt 0.42) { $mapLive } elseif ($v -lt 0.58) { $mapRec } elseif ($v -lt 0.63) { $mapMeta } else { $mapEmpty }
  $g.FillRectangle((New-Object Drawing.SolidBrush $color), [float]($x0 + $c * $pitch), [float]($y0 + $r * $pitch), [float]$cell, [float]$cell)
}
Draw-Mark $g (($w - 72) / 2) 34 72
$fmt = New-Object Drawing.StringFormat; $fmt.Alignment = "Center"
$g.DrawString($Product, (New-Font 28 ([Drawing.FontStyle]::Bold)), (New-Object Drawing.SolidBrush $text), (New-Object Drawing.RectangleF(0, 116, $w, 38)), $fmt)
$g.DrawString($Tagline, (New-Font 12.5 ([Drawing.FontStyle]::Regular)), (New-Object Drawing.SolidBrush $sub), (New-Object Drawing.RectangleF(8, 154, ($w - 16), 40)), $fmt)
$bmp.Save((Join-Path $here "sidebar.bmp"), [Drawing.Imaging.ImageFormat]::Bmp)
$g.Dispose(); $bmp.Dispose()

# --- Page header: 150 x 57 (right side of a white header band) ---
$w = 150; $h = 57
$bmp = New-Object Drawing.Bitmap($w, $h, [Drawing.Imaging.PixelFormat]::Format24bppRgb)
$g = [Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = "AntiAlias"; $g.TextRenderingHint = "AntiAliasGridFit"
$g.Clear([Drawing.Color]::White)
Draw-Mark $g 103 9.5 38
$fmtR = New-Object Drawing.StringFormat; $fmtR.Alignment = "Far"; $fmtR.LineAlignment = "Center"
$g.DrawString($Product, (New-Font 19 ([Drawing.FontStyle]::Bold)), (New-Object Drawing.SolidBrush $ink), (New-Object Drawing.RectangleF(0, 8, 96, 41)), $fmtR)
$bmp.Save((Join-Path $here "header.bmp"), [Drawing.Imaging.ImageFormat]::Bmp)
$g.Dispose(); $bmp.Dispose()
"art written to $here"
