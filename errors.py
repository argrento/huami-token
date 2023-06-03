# Copyright (c) 2021-2023 Kirill Snezhko

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Module for storing error messages"""

ERRORS = {
    "0106" : "0106. Verification failed, wrong token.",
    "0113" : "0113. Wrong region.",
    "0115" : "0115. Account disabled.",
    "0117" : "0117. Account not registered.",

    # Mi Fitness Error codes
    "0"    : "0. No error.",
	"304"  : "304. Same version code.",
	"10016": "10016. Lack of parameter.",
	"10017": "10017. Illegal parameter.",
	"10031": "10031. User restricted.",
	"20023": "20023. User behavior blocked.",
	"20031": "20031. Captcha required.",
	"21317": "21317. Invalid token.",
	"60018": "60018. Invalid parameters.",
	"66108": "66108. Invalid user profile.",
	"70002": "70002. No password.",
	"70003": "70003. Invalid password format.",
	"70008": "70008. Invalid phone.",
	"70009": "70009. Empty phone parameter.",
	"70016": "70016. Password error.",
	"70017": "70017. Error with FID nonce.",
	"70022": "70022. Reach limit.",
	"70055": "70055. Risky password.",
	"70056": "70056. Password includes phone number or email.",
	"85110": "85110. Password repeat error.",
	"87001": "87001. Wrong captcha."
}
