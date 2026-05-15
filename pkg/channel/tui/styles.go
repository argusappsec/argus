package tui

import "github.com/charmbracelet/lipgloss"

// styles centralises every lipgloss rule used by the TUI. Keeping them in one
// place makes the visual identity easy to tweak and (later) themeable.
type styles struct {
	app        lipgloss.Style
	historyBox lipgloss.Style
	inputBox   lipgloss.Style
	statusBar  lipgloss.Style

	userPrompt   lipgloss.Style
	userBody     lipgloss.Style
	agentPrompt  lipgloss.Style
	agentBody    lipgloss.Style
	toolPrefix   lipgloss.Style
	toolBody     lipgloss.Style
	systemPrefix lipgloss.Style
	systemBody   lipgloss.Style
	errorPrefix  lipgloss.Style
	errorBody    lipgloss.Style

	statusLabel  lipgloss.Style
	statusValue  lipgloss.Style
	statusWork   lipgloss.Style
	statusDivide lipgloss.Style
}

// newStyles builds the default Claude-Code-inspired palette.
func newStyles() styles {
	cyan := lipgloss.Color("#7ee5e5")
	violet := lipgloss.Color("#c79df1")
	grey := lipgloss.Color("#9a9a9a")
	dim := lipgloss.Color("#666666")
	yellow := lipgloss.Color("#e0c060")
	red := lipgloss.Color("#e07070")
	border := lipgloss.Color("#3a3a3a")

	return styles{
		app: lipgloss.NewStyle(),

		historyBox: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(border).
			Padding(0, 1),

		inputBox: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(border).
			Padding(0, 1),

		statusBar: lipgloss.NewStyle().
			Foreground(grey).
			Padding(0, 1),

		userPrompt:  lipgloss.NewStyle().Foreground(cyan).Bold(true),
		userBody:    lipgloss.NewStyle(),
		agentPrompt: lipgloss.NewStyle().Foreground(violet).Bold(true),
		agentBody:   lipgloss.NewStyle(),
		toolPrefix:  lipgloss.NewStyle().Foreground(dim),
		toolBody:    lipgloss.NewStyle().Foreground(grey),

		systemPrefix: lipgloss.NewStyle().Foreground(yellow).Bold(true),
		systemBody:   lipgloss.NewStyle().Foreground(yellow),
		errorPrefix:  lipgloss.NewStyle().Foreground(red).Bold(true),
		errorBody:    lipgloss.NewStyle().Foreground(red),

		statusLabel:  lipgloss.NewStyle().Foreground(dim),
		statusValue:  lipgloss.NewStyle().Foreground(grey),
		statusWork:   lipgloss.NewStyle().Foreground(yellow),
		statusDivide: lipgloss.NewStyle().Foreground(border),
	}
}
