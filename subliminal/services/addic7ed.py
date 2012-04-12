# -*- coding: utf-8 -*-
# Copyright 2012 Olifozzy <olifozzy@gmail.com>
#
# This file is part of subliminal.
#
# subliminal is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# subliminal is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with subliminal.  If not, see <http://www.gnu.org/licenses/>.
from . import ServiceBase
from ..subtitles import get_subtitle_path, ResultSubtitle
from ..videos import Episode
from subliminal.utils import get_keywords, split_keyword
from ..bs4wrapper import BeautifulSoup
from ..cache import cachedmethod
import guessit
import logging
import re
import unicodedata
import urllib


logger = logging.getLogger(__name__)

def match(pattern, string):
    try:
        return re.search(pattern, string).group(1)
    except AttributeError:
        logger.debug("Could not match '%s' on '%s'" % (pattern, string))
        return None

def matches(pattern, string):
    try:
        return re.search(pattern, string).group(1,2)
    except AttributeError:
        logger.debug("Could not match '%s' on '%s'" % (pattern, string))
        return None

class Addic7ed(ServiceBase):
    server_url = 'http://www.addic7ed.com'
    api_based = False
    languages = {u'English': 'en',
            u'English (US)': 'en',
            u'English (UK)': 'en',
            u'Italian': 'it',
            u'Portuguese': 'pt',
            u'Portuguese (Brazilian)': 'pt',
            u'Romanian': 'ro',
            u'Español (Latinoamérica)': 'es',
            u'Español (España)': 'es',
            u'Spanish (Latin America)': 'es',
            u'Español': 'es',
            u'Spanish': 'es',
            u'Spanish (Spain)': 'es',
            u'French': 'fr',
            u'Greek': 'el',
            u'Arabic': 'ar',
            u'German': 'de',
            u'Croatian': 'hr',
            u'Indonesian': 'id',
            u'Hebrew': 'he',
            u'Russian': 'ru',
            u'Turkish': 'tr',
            u'Swedish': 'se',
            u'Czech': 'cs',
            u'Dutch': 'nl',
            u'Hungarian': 'hu',
            u'Norwegian': 'no',
            u'Polish': 'pl',
            u'Persian': 'fa'}
    reverted_languages = True
    videos = [Episode]
    require_video = False

    def guess_language(self, lang):
        if lang in Addic7ed.languages:
            return guessit.Language(Addic7ed.languages[lang])
        return guessit.Language(lang, strict=False)

    @cachedmethod
    def get_likely_series_id(self, name):
        r = self.session.get('%s/shows.php' % self.server_url)
        soup = BeautifulSoup(r.content, 'lxml')
        for elem in soup.find_all('h3'):
            show_name = elem.a.text.lower()
            show_id = int(match('show/([0-9]+)', elem.a['href']))
            # we could just return the id of the queried show, but as we
            # already downloaded the whole page we might as well fill in the
            # information for all the shows
            self.cache_for(self.get_likely_series_id,
                           args = (show_name,),
                           result = show_id)
        return self.cached_value(self.get_likely_series_id, args = (name,))


    @cachedmethod
    def get_episode_url(self, series_id, season, number):
        """Get the Addic7ed id for the given episode. Raises KeyError if none
        could be found."""
        # download the page of the show, contains ids for all episodes all seasons
        episode_id = None
        subtitle_ids = []
        r = self.session.get('%s/show/%d' % (self.server_url, series_id))
        soup = BeautifulSoup(r.content, 'lxml')
        form = soup.find('form', attrs={'name': 'multidl'})
        for table in form.find_all('table'):

            for row in table.find_all('tr'):
                cell = row.find('td', 'MultiDldS')
                if not cell:
                    continue
                m = matches('/serie/.+/([0-9]+)/([0-9]+)/', cell.a['href'])
                if not m:
                    continue
                episode_url = cell.a['href']
                season_number = int(m[0])
                episode_number = int(m[1])
                # we could just return the url of the queried episode, but as we
                # already downloaded the whole page we might as well fill in the
                # information for all the episodes of the show
                self.cache_for(self.get_episode_url,
                               args = (series_id, season_number, episode_number),
                               result = episode_url)

        # raises KeyError if not found
        return self.cached_value(self.get_episode_url, args = (series_id, season, number))

    # Do not cache this method in order to always check for the most recent
    # subtitles
    def get_sub_urls(self, episode_url):
        suburls = []
        r = self.session.get('%s/%s' % (self.server_url, episode_url))
        epsoup = BeautifulSoup(r.content, 'lxml')
        for releaseTable in epsoup.find_all('table', 'tabel95'):
            releaseRow = releaseTable.find('td', 'NewsTitle')
            if not releaseRow :
                continue
            release = releaseRow.text.strip()
            for row in releaseTable.find_all('tr'):
                link = row.find('a', 'buttonDownload')
                if not link:
                    continue
                if 'href' not in link.attrs or not (link['href'].startswith('/original') or link['href'].startswith('/updated')):
                    continue

                suburl = link['href']

                lang = row.find('td','language').text.strip()
                result = { 'suburl': suburl, 'language': lang, 'release': release }
                suburls.append(result)

        return suburls


    def list(self, video, languages):
        if not self.check_validity(video, languages):
            return []
        results = self.query(video.path or video.release, languages, get_keywords(video.guess), video.series, video.season, video.episode)
        return results


    def download(self, subtitle):
        """Download a subtitle"""
        self.download_file(subtitle.link, subtitle.path)


    def query(self, filepath, languages, keywords, series, season, episode):
        logger.debug(u'Getting subtitles for %s season %d episode %d with languages %r' % (series, season, episode, languages))
        self.init_cache()
        try:
            sid = self.get_likely_series_id(series.lower())
        except KeyError:
            logger.debug('Could not find series id for %s' % series)
            return []

        try:
            ep_url = self.get_episode_url(sid, season, episode)
        except KeyError:
            logger.debug('Could not find episode id for %s season %d epnumber %d' % (series, season, episode))
            return []
        suburls = self.get_sub_urls(ep_url)

        # filter the subtitles with our queried languages
        languages = set(guessit.Language(l, strict=False) for l in languages)
        subtitles = []
        for suburl in suburls:
            language = self.guess_language(suburl['language'])
            if language not in languages:
                continue

            path = get_subtitle_path(filepath, language.alpha2, self.config.multi)
            subtitle = ResultSubtitle(path, language.alpha2, self.__class__.__name__.lower(),
                                      '%s/%s' % (self.server_url, suburl['suburl']),
                                      keywords=[suburl['release'] ])
            subtitles.append(subtitle)

        return subtitles

Service = Addic7ed
