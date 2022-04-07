#!/usr/bin/python3

import re
import json
import random
import argparse
import requests
import colorama

YELLOW = "\033[33m"
RED = "\033[31m"
BOLD       = "\033[1m"

def parse_arguments():
    parser = argparse.ArgumentParser(description='Bot to solve puzzle game on chess.com website (do not works on free account)')
    parser.add_argument("--token", "-t", help="PHPSessid", required=True)
    parser.add_argument("--number", "-n", help="Number of puzzle to solve", default=10)
    parser.add_argument("--proxy", "-P", help="Activate proxy (harcoded 127.0.0.1:8080) for BurpSuite debug", action='store_true')
    return  parser.parse_args()


def perform_request(method, url, headers, cookies, post_param, data):
    '''
    generic call to request library
    '''

    if method == 'get':
        if args.proxy == True:
            return requests.get(url, headers=headers, cookies=cookies, data=data, proxies={'https': 'https://127.0.0.1:8080'}, verify=False)
        else:
            return requests.get(url, headers=headers, cookies=cookies, data=data)
    elif method == 'post':
        if args.proxy == True:
            return requests.post(url, headers=headers, cookies=cookies, json=post_param, data=data, proxies={'https': 'https://127.0.0.1:8080'}, verify=False)
        else:
            return requests.post(url, headers=headers, cookies=cookies, json=post_param, data=data)


def solve_puzzle(token):
    '''
    solve a puzzle game
    Add randomness and delay when solving problem in order to not be detected and ban by chesscom
       - hint usage : 1/50
       - puzzle failed : 1/13
       - time to solve problem : 4-12 sec
    '''
    source_code = json.loads(perform_request('get', "https://www.chess.com:443/callback/tactics/rated/next", {}, {"PHPSESSID": token}, {}, {}).text)

    url = 'https://www.chess.com:443/callback/tactics/submitMoves'
    hint = 0
    if random.randint(1, 50) == 10:
        hint = 1
    post_param={
        "_token": get_csrf_token(token),
        "isSolvedWithHint": hint,
        "moves": source_code['tcnMoveList'],
        "tacticsProblemId": source_code['id'],
        "totalTime": random.randint(4, 12)
    }

    # avoid detection : fail problem 1/20
    if random.randint(1, 20) == 2:
        post_param['moves'] = 't2c5'

    source_code = json.loads(perform_request('post', url, {"Content-Type": "application/json"}, {"PHPSESSID": token}, post_param, {}).text)
    if source_code['result'] == 'solved':
        print(display_colored_text(YELLOW, '[+] ') + 'Puzzle ' + str(source_code['newRatingInfo']['problem']['current']) + ' elo solved.')
    else:
        print(display_colored_text(RED, '[-] ') + 'Puzzle ' + str(source_code['newRatingInfo']['problem']['current']) + ' elo failed.')
    print(display_colored_text(BOLD, '    User elo : ' + str(get_elo(token))))


def get_csrf_token(token):
    '''
    return CSRF token
    '''

    source_code = perform_request('get', "https://www.chess.com:443/puzzles", {}, {"PHPSESSID": token}, {}, {}).text
    return re.search('"token":"(.*)","logout":', source_code, re.IGNORECASE).group(1)


def get_elo(token):
    '''
    Return current elo
    '''

    url = "https://www.chess.com:443/callback/tactics/stats/user"
    cookies = {"PHPSESSID": token}
    r = perform_request('get', url, {}, cookies, {}, {})
    return str(json.loads(r.text)['rating'])


def display_colored_text(color, text):
    '''
    add color to print output on shell
    '''

    colored_text = f"\033[{color}{text}\033[00m"
    return colored_text


def main():
    global args
    args = parse_arguments()

    for i in range(int(args.number)):
        solve_puzzle(args.token)


main()
