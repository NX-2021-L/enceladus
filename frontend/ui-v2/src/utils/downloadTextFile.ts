/**
 * Client-side text-file download (ENC-TSK-M34 AC-2: ".md download" button).
 * Builds a Blob from already-fetched text and triggers a browser download via
 * a transient <a download> — no extra network round-trip, no auth/CORS
 * concerns since the content is already in hand from the record fetch.
 */
export function downloadTextFile(fileName: string, text: string, mimeType = 'text/markdown'): void {
  const blob = new Blob([text], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = fileName
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}
