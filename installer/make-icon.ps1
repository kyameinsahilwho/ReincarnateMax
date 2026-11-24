# Draws icons/source.png (1024x1024): the MAX mark, a violet tile holding a sector grid in which a
# diagonal run of cells is "recovered" (bright) - the Recovery Map in miniature.
# Then: npx -y @tauri-apps/cli@2 icon icons/source.png -o icons
Add-Type -AssemblyName System.Drawing
$size = 1024
$bmp = New-Object Drawing.Bitmap($size, $size, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = [Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([Drawing.Color]::Transparent)

function RoundRect($x, $y, $w, $h, $r) {
  $p = New-Object Drawing.Drawing2D.GraphicsPath
  $d = $r * 2
  $p.AddArc($x, $y, $d, $d, 180, 90)
  $p.AddArc(($x + $w - $d), $y, $d, $d, 270, 90)
  $p.AddArc(($x + $w - $d), ($y + $h - $d), $d, $d, 0, 90)
  $p.AddArc($x, ($y + $h - $d), $d, $d, 90, 90)
  $p.CloseFigure()
  return $p
}

$tile = RoundRect 64 64 896 896 200
$bg = New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(255, 44, 32, 92))
$g.FillPath($bg, $tile)

$n = 6
$gap = 26
$area = 620
$cell = ($area - ($n - 1) * $gap) / $n
$ox = (1024 - $area) / 2
$oy = (1024 - $area) / 2
$dim = New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(255, 78, 64, 140))
$lit = New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(255, 190, 176, 255))
$hot = New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(255, 255, 214, 102))
for ($r = 0; $r -lt $n; $r++) {
  for ($c = 0; $c -lt $n; $c++) {
    $x = $ox + $c * ($cell + $gap)
    $y = $oy + $r * ($cell + $gap)
    $brush = $dim
    # An "M" drawn by lit cells: both outer columns plus the two diagonals meeting in row 2.
    if ($c -eq 0 -or $c -eq ($n - 1)) { $brush = $lit }
    if (($r -eq $c -and $r -le 2) -or ($r + $c -eq ($n - 1) -and $r -le 2)) { $brush = $lit }
    if ($r -eq 2 -and ($c -eq 2 -or $c -eq 3)) { $brush = $hot }
    $p = RoundRect $x $y $cell $cell 18
    $g.FillPath($brush, $p)
  }
}
$g.Dispose()
$out = Join-Path $PSScriptRoot "..\icons\source.png"
$bmp.Save($out, [Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "wrote $out"
