import os
import re
from html import escape

# Input Markdown file
README_FILE = "../../README.md"

# Output file
BOOKMARKS_FILE = "../../supreme_detection_engineer_bookmarks.html"

def parse_markdown_to_links(markdown_file):
    """Parse the Markdown file and extract links organized by sections."""
    with open(markdown_file, "r", encoding="utf-8") as f:
        content = f.read()

    links_by_section = {}
    current_section = None

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#"):
            # Extract section title from Markdown headers
            current_section = line.lstrip("# ").strip()
            if not(current_section.startswith("Supreme Detection Engineer")) and current_section not in ["Contents"]:
                links_by_section[current_section] = []
        elif line.startswith("- [") and "](http" in line:
            # Extract Markdown link format: [name](url)
            matches = re.findall(r"\[([^\]]+)\]\((http[s]?://[^\)]+)\)", line)
            for match in matches:
                if match and current_section:
                    links_by_section[current_section].append((match[1], match[0]))
    for section in links_by_section:
        links_by_section[section].sort(key=lambda x: x[1].lower())
    return links_by_section

def create_bookmark_html(links_by_section, title):
    """Generate an HTML file for browser bookmarks."""
    html = [
        "<!DOCTYPE NETSCAPE-Bookmark-file-1>",
        "<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">",
        f"<TITLE>{escape(title)}</TITLE>",
        "<H1>{escape(title)}</H1>",
        "<DL><p>",
        "  <DT><H3>Supreme Detection Engineer</H3>",
        "  <DL><p>"
    ]

    for section, links in links_by_section.items():
        html.append(f"    <DT><H3>{escape(section)}</H3>")
        html.append("    <DL><p>")
        for url, name in links:
            html.append(f"      <DT><A HREF=\"{escape(url)}\">{escape(name)}</A>")
        html.append("    </DL><p>")

    html.append("  </DL><p>")
    html.append("</DL><p>")
    return "\n".join(html)

def main():
    if not os.path.exists(README_FILE):
        print(f"Error: {README_FILE} does not exist.")
        return
    
    links_by_section = parse_markdown_to_links(README_FILE)

    # Generate bookmarks
    bookmarks_html = create_bookmark_html(links_by_section, "Browser Bookmarks")
    with open(BOOKMARKS_FILE, "w", encoding="utf-8") as f:
        f.write(bookmarks_html)

    print(f"Bookmarks generated: {BOOKMARKS_FILE}")

if __name__ == "__main__":
    main()