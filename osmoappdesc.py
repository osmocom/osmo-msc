#!/usr/bin/env python3

# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import os

app_configs = {
    "msc": ["doc/examples/osmo-msc/osmo-msc.cfg"],
}

if os.environ["IU"] == "1":
    app_configs["msc"] += ["doc/examples/osmo-msc/osmo-msc_custom-sccp.cfg",
                           "doc/examples/osmo-msc/osmo-msc_multi-cs7.cfg"]

apps = [(4254, "src/osmo-msc/osmo-msc", "OsmoMSC", "msc"),
        ]

vty_command = ["./src/osmo-msc/osmo-msc", "-c",
               "doc/examples/osmo-msc/osmo-msc.cfg"]

vty_app = apps[0] # reference apps[] entry for osmo-msc
