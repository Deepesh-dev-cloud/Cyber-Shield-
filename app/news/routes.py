
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import requests
import feedparser
from bs4 import BeautifulSoup
from flask import render_template

from app.news import news


# Cybersecurity news sources
FEEDS = [
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
    },
    {
        "name": "CISA Security Alerts",
        "url": "https://www.cisa.gov/cybersecurity-advisories/alerts.xml",
    },
]


def parse_date(value):
    """Convert a published date into a timezone-aware datetime."""
    if not value:
        return None

    try:
        date = parsedate_to_datetime(value)

        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)

        return date

    except (ValueError, TypeError, OverflowError):
        return None


def get_news():
    """Fetch and combine articles from the configured RSS feeds."""
    articles = []
    errors = []

    headers = {
        "User-Agent": "CyberShield/1.0 SecurityNewsReader"
    }

    for feed in FEEDS:
        try:
            response = requests.get(
                feed["url"],
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()

            parsed_feed = feedparser.parse(response.content)

            # Record feeds that cannot be parsed.
            if parsed_feed.bozo and not parsed_feed.entries:
                errors.append(feed["name"])
                continue

            for entry in parsed_feed.entries[:15]:
                title = entry.get("title", "Untitled article")
                link = entry.get("link", "")
                summary = entry.get("summary", "")

                published_text = (
                    entry.get("published")
                    or entry.get("updated")
                    or ""
                )

                # Accept only HTTPS article links with a hostname.
                parsed_url = urlparse(link)

                if (
                    parsed_url.scheme != "https"
                    or not parsed_url.hostname
                ):
                    continue

                # Remove HTML markup from article summaries.
                summary = BeautifulSoup(
                    summary,
                    "html.parser",
                ).get_text(" ", strip=True)

                articles.append({
                    "title": title,
                    "link": link,
                    "summary": summary[:500],
                    "source": feed["name"],
                    "published": published_text,
                    "date": parse_date(published_text),
                })

        except (
            requests.RequestException,
            ValueError,
            TypeError,
        ):
            # Keep other feeds working if one source fails.
            errors.append(feed["name"])

    # Sort newest articles first.
    articles.sort(
        key=lambda article: (
            article["date"] is not None,
            article["date"] or datetime.min.replace(
                tzinfo=timezone.utc
            ),
        ),
        reverse=True,
    )

    return articles[:30], errors


# Cybersecurity News page
@news.route("/news", methods=["GET"])
def news_home():
    articles, errors = get_news()

    response = render_template(
        "news.html",
        articles=articles,
        errors=errors,
    )

    return response
