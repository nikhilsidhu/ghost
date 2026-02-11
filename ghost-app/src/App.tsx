export default function App() {
  return (
    <div class="h-screen flex flex-col" style={{ background: "var(--neutral-950)" }}>
      <div data-tauri-drag-region class="h-10 flex-shrink-0" />
      <div class="flex-1 flex items-center justify-center">
        <span class="text-sm" style={{ color: "var(--neutral-400)" }}>ghost</span>
      </div>
    </div>
  );
}
