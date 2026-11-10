import { Button as ButtonPrimitive } from "@base-ui/react/button"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "cn"

const buttonVariants = cva(
  "group/button inline-flex shrink-0 items-center justify-center rounded-lg border border-transparent bg-clip-padding font-sans text-base leading-normal font-semibold whitespace-nowrap select-none disabled:opacity-70 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
      default: "border-primary bg-primary text-primary-foreground hover:bg-primary-hover",
        outline:
        "border-input bg-card text-foreground hover:bg-secondary aria-expanded:bg-secondary",
        secondary:
        "bg-secondary text-secondary-foreground hover:bg-secondary aria-expanded:bg-secondary",
        ghost:
        "bg-transparent text-muted-foreground hover:bg-secondary hover:text-foreground aria-expanded:bg-secondary",
        destructive:
        "border-destructive bg-card text-destructive hover:bg-secondary",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default:
        "min-h-12 gap-2 px-4 py-3",
      xs: "min-h-11 gap-1 px-2 py-2 text-sm",
      sm: "min-h-11 gap-2 px-3 py-2 text-sm",
      lg: "min-h-12 gap-2 px-6 py-3",
      icon: "size-12",
        "icon-xs":
        "size-11 [&_svg:not([class*='size-'])]:size-3",
        "icon-sm":
        "size-11",
      "icon-lg": "size-12",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  ...props
}: ButtonPrimitive.Props & VariantProps<typeof buttonVariants>) {
  return (
    <ButtonPrimitive
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
