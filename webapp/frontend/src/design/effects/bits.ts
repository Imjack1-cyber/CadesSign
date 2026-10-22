/**
 * Short-lived particles shared by the presets: splashes, sparks, puffs, trails and rings. Each one
 * flies with its own velocity, optional gravity and drag, and fades out over its life.
 */

export type BitShape = 'dot' | 'ring' | 'heart' | 'streak' | 'star' | 'square'

export interface Bit {
  x: number
  y: number
  vx: number
  vy: number
  /** Seconds left, and the life it started with (for fading). */
  life: number
  max: number
  size: number
  color: string
  shape: BitShape
  gravity: number
  /** Rings grow by this many px per second. */
  grow: number
}

export const MAX_BITS = 600

/** Scales a particle count to the screen: a phone gets about a third of a 1280×800 desktop's. */
export function scaleCount(world: { w: number; h: number }, n: number) {
  const density = Math.min(1, Math.max(0.35, (world.w * world.h) / (1280 * 800)))
  return Math.max(8, Math.round(n * density))
}

export function spawnBit(bits: Bit[], b: Partial<Bit> & Pick<Bit, 'x' | 'y'>) {
  if (bits.length >= MAX_BITS) bits.shift()
  const life = b.life ?? 0.8
  bits.push({
    vx: 0, vy: 0, size: 3, color: '#fff', shape: 'dot', gravity: 0, grow: 0, ...b, life, max: b.max ?? life,
  })
}

/** A ring of `count` bits flying outwards from (x, y). */
export function burstBits(
  bits: Bit[], rnd: () => number, x: number, y: number, count: number, speed: number, b: Partial<Bit> = {},
) {
  for (let i = 0; i < count; i++) {
    const a = (i / count) * Math.PI * 2 + rnd() * 0.4
    const v = speed * (0.5 + rnd() * 0.7)
    spawnBit(bits, { x, y, vx: Math.cos(a) * v, vy: Math.sin(a) * v, life: 0.6 + rnd() * 0.6, ...b })
  }
}

export function stepBits(bits: Bit[], dt: number) {
  for (let i = bits.length - 1; i >= 0; i--) {
    const b = bits[i]
    b.life -= dt
    if (b.life <= 0) {
      bits.splice(i, 1)
      continue
    }
    b.vy += b.gravity * dt
    b.vx *= 1 - 1.5 * dt
    b.x += b.vx * dt
    b.y += b.vy * dt
    b.size += b.grow * dt
  }
}

function heart(ctx: CanvasRenderingContext2D, x: number, y: number, s: number) {
  ctx.beginPath()
  ctx.moveTo(x, y + s * 0.35)
  ctx.bezierCurveTo(x - s, y - s * 0.4, x - s * 0.4, y - s, x, y - s * 0.35)
  ctx.bezierCurveTo(x + s * 0.4, y - s, x + s, y - s * 0.4, x, y + s * 0.35)
  ctx.fill()
}

function star(ctx: CanvasRenderingContext2D, x: number, y: number, s: number) {
  ctx.beginPath()
  for (let i = 0; i < 8; i++) {
    const r = i % 2 ? s * 0.35 : s
    const a = (i / 8) * Math.PI * 2
    ctx.lineTo(x + Math.cos(a) * r, y + Math.sin(a) * r)
  }
  ctx.closePath()
  ctx.fill()
}

export function drawBits(ctx: CanvasRenderingContext2D, bits: Bit[]) {
  for (const b of bits) {
    ctx.globalAlpha = Math.max(0, Math.min(1, b.life / b.max))
    ctx.fillStyle = b.color
    ctx.strokeStyle = b.color
    switch (b.shape) {
      case 'ring':
        ctx.lineWidth = 2
        ctx.beginPath()
        ctx.arc(b.x, b.y, b.size, 0, Math.PI * 2)
        ctx.stroke()
        break
      case 'heart':
        heart(ctx, b.x, b.y, b.size)
        break
      case 'star':
        star(ctx, b.x, b.y, b.size)
        break
      case 'streak':
        ctx.lineWidth = b.size
        ctx.lineCap = 'round'
        ctx.beginPath()
        ctx.moveTo(b.x, b.y)
        ctx.lineTo(b.x - b.vx * 0.05, b.y - b.vy * 0.05)
        ctx.stroke()
        break
      case 'square':
        ctx.fillRect(b.x - b.size / 2, b.y - b.size / 2, b.size, b.size)
        break
      default:
        ctx.beginPath()
        ctx.arc(b.x, b.y, b.size, 0, Math.PI * 2)
        ctx.fill()
    }
  }
  ctx.globalAlpha = 1
}
