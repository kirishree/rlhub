# Custom flowable for colored rectangle for horizontal bar
class UptimeBar(Flowable):
    def __init__(self, uptime_percent, width=15, height=10):
        Flowable.__init__(self)
        self.uptime_percent = float(uptime_percent)
        self.width = width
        self.height = height

    def draw(self):
        # Choose color based on uptime
        if self.uptime_percent >= 100:
            fill_color = colors.green
        elif self.uptime_percent > 98:
            fill_color = colors.yellow
        else:
            fill_color = colors.red

        self.canv.setFillColor(fill_color)
        self.canv.rect(0, 0, self.width, self.height, stroke=0, fill=1)