import {
  cloneElement,
  forwardRef,
  isValidElement,
  useId,
  type InputHTMLAttributes,
  type ReactElement,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import clsx from "clsx";
import { ChevronDown } from "lucide-react";
import { controlBase } from "./styles";

type ControlSize = "sm" | "md";
const HEIGHT: Record<ControlSize, string> = { sm: "h-8", md: "h-9" };

export interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "size"> {
  controlSize?: ControlSize;
  invalid?: boolean;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { controlSize = "md", invalid, className, ...rest },
  ref
) {
  return (
    <input
      ref={ref}
      aria-invalid={invalid || undefined}
      className={clsx(controlBase, HEIGHT[controlSize], className)}
      {...rest}
    />
  );
});

export interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  invalid?: boolean;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(function Textarea(
  { invalid, className, ...rest },
  ref
) {
  return (
    <textarea
      ref={ref}
      aria-invalid={invalid || undefined}
      className={clsx(controlBase, "py-2 leading-relaxed", className)}
      {...rest}
    />
  );
});

export interface SelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, "size"> {
  controlSize?: ControlSize;
  invalid?: boolean;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { controlSize = "md", invalid, className, children, ...rest },
  ref
) {
  return (
    <div className={clsx("relative", className)}>
      <select
        ref={ref}
        aria-invalid={invalid || undefined}
        className={clsx(controlBase, HEIGHT[controlSize], "cursor-pointer appearance-none pr-9")}
        {...rest}
      >
        {children}
      </select>
      <ChevronDown
        aria-hidden="true"
        className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-muted"
      />
    </div>
  );
});

export interface FieldProps {
  label: ReactNode;
  /** Helper text under the control. */
  hint?: ReactNode;
  /** Error text; also marks the control invalid and links it via aria-describedby. */
  error?: ReactNode;
  className?: string;
  /** A single Input/Select/Textarea; it receives the generated id + aria wiring. */
  children: ReactElement;
}

/** Label + control + hint/error, with the id/aria-describedby wiring done for you. */
export function Field({ label, hint, error, className, children }: FieldProps) {
  const autoId = useId();
  const childProps = (isValidElement(children) ? children.props : {}) as {
    id?: string;
    "aria-describedby"?: string;
  };
  const id = childProps.id ?? autoId;
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy =
    [childProps["aria-describedby"], hintId, errorId].filter(Boolean).join(" ") || undefined;

  return (
    <div className={clsx("flex flex-col gap-1.5", className)}>
      <label htmlFor={id} className="text-sm font-semibold text-fg-secondary">
        {label}
      </label>
      {cloneElement(children as ReactElement<Record<string, unknown>>, {
        id,
        "aria-describedby": describedBy,
        ...(error ? { invalid: true } : {}),
      })}
      {hint && !error && (
        <p id={hintId} className="text-xs text-fg-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
