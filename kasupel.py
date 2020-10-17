"""A Python wrapper for the API."""
from __future__ import annotations

import base64
import collections
import datetime
import enum
import functools
import json
import os
import typing

import aiohttp

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

import socketio


Json = typing.Dict[str, typing.Any]


def load_timestamp(seconds: int) -> datetime.datetime:
    """Load a datetime from an int."""
    if seconds is None:
        return None
    return datetime.datetime.fromtimestamp(seconds)


def dump_timestamp(x: datetime.datetime) -> int:
    """Convert a datetime to an int."""
    return int(x.timestamp())


def load_timedelta(seconds: int) -> datetime.timedelta:
    """Load a timedelta from an int."""
    if seconds is None:
        return None
    return datetime.timedelta(seconds=seconds)


def dump_timedelta(x: datetime.timedelta) -> int:
    """Convert a timedelta to an int."""
    return int(x.total_seconds())


class RequestError(Exception):
    """A class for errors caused by a bad request."""

    def __init__(self, error: Json):
        """Store the code and message to be handled."""
        self.code = error['error']
        self.message = error['message']
        super().__init__(f'ERR{self.code}: {self.message}.')


class Gamemode(enum.Enum):
    """An enum for the mode of a game."""

    CHESS = enum.auto()

    @property
    def move_class(self) -> Move:
        """Get the relevant class for moves."""
        return {
            self.CHESS: ChessMove
        }[self]


class Winner(enum.Enum):
    """An enum for the winner of a game."""

    GAME_NOT_COMPLETE = enum.auto()
    HOME = enum.auto()
    AWAY = enum.auto()
    DRAW = enum.auto()


class Conclusion(enum.Enum):
    """An enum for the way a game finished."""

    GAME_NOT_COMPLETE = enum.auto()
    CHECKMATE = enum.auto()
    RESIGN = enum.auto()
    TIME = enum.auto()
    STALEMATE = enum.auto()
    THREEFOLD_REPETITION = enum.auto()
    FIFTY_MOVE_RULE = enum.auto()
    AGREED_DRAW = enum.auto()


class Side(enum.Enum):
    """An enum for home/away."""

    HOME = enum.auto()
    AWAY = enum.auto()


class Piece(enum.Enum):
    """An enum for a chess piece type."""

    PAWN = enum.auto()
    ROOK = enum.auto()
    KNIGHT = enum.auto()
    BISHOP = enum.auto()
    QUEEN = enum.auto()
    KING = enum.auto()


class Event(enum.Enum):
    """An enum for an incoming event."""

    DISCONNECT = enum.auto()
    GAME_START = enum.auto()
    GAME_END = enum.auto()
    DRAW_OFFER = enum.auto()
    MOVE = enum.auto()


class DisconnectReason(enum.Enum):
    """An reason for being disconnected."""

    INVITE_DECLINED = enum.auto()
    NEW_CONNECTION = enum.auto()
    GAME_OVER = enum.auto()


class Client:
    """A client connected to the server."""

    def __init__(self, url: str):
        """Initialise the client with the URL of the server."""
        self.url = url
        self._aiohttp_session = aiohttp.ClientSession()

    @property
    def aiohttp_session(self):
        """Get the aiohttp session, ensuring that it's open."""
        if self._aiohttp_session.closed:
            self._aiohttp_session = aiohttp.ClientSession()
        return self._aiohttp_session

    async def _post_payload(
            self, endpoint: str, payload: Json, method: str = 'POST',
            encrypted: bool = False) -> Json:
        """Encrypt a payload and send it to the server."""
        data = json.dumps(payload, separators=(',', ':')).encode()
        if encrypted:
            data = self._public_key().encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        method = {
            'POST': self.aiohttp_session.post,
            'PATCH': self.aiohttp_session.patch
        }[method]
        async with method(self.url + endpoint, data=data) as response:
            return self._handle_response(response)

    def _handle_response(self, response: aiohttp.ClientResponse) -> Json:
        """Handle a response from the server."""
        if response.ok:
            if response.status_code == 204:
                return {}
            else:
                return response.json()
        raise RequestError(response.json())

    @functools.lru_cache(1)    # Cache with size 1 since it won't change.
    async def _public_key(self) -> rsa.RSAPublicKey:
        """Get the server's public key."""
        async with self.aiohttp_session.get(self.url + '/rsa_key') as resp:
            return serialization.load_pem_public_key(resp.text)

    async def login(self, username: str, password: str) -> Session:
        """Log in to an account."""
        token = base64.b64encode(os.urandom(32)).decode()
        resp = await self._post_payload('/accounts/login', {
            'username': username,
            'password': password,
            'token': token
        }, encrypted=True)
        session_id = resp['session_id']
        return Session(self, token, session_id)

    async def get_user(
            self, username: str = None, user_id: int = None) -> User:
        """Get a user's account."""
        if not bool(username) ^ bool(id):
            raise TypeError('Exactly one of username or id should be passed.')
        if username:
            request = self.aiohttp_session.get(self.url + '/user/' + username)
        else:
            request = self.aiohttp_session.get(
                self.url + '/accounts/account', params={'id': user_id}
            )
        async with request as response:
            return User(self, self._handle_response(response))

    async def get_game(self, game_id: int) -> Game:
        """Get a game by ID."""
        url = self.url + '/games/' + str(game_id)
        async with self.aiohttp_session.get(url) as resp:
            return Game(self, self._handle_response(resp))

    def get_users(self, start_page: int = 0) -> Paginator:
        """Get a list of all users."""
        return Paginator(self, '/accounts/all', 'users', User, start_page)

    async def create_account(self, username: str, password: str, email: str):
        """Create a new user account."""
        await self._post_payload('/accounts/create', {
            'username': username,
            'password': password,
            'email': email
        }, encrypted=True)

    def on(self, event: Event) -> typing.Callable:
        """Register a socket event listener.

        This will only ever be called if you create and connect a
        GameConnection instance.
        """
        return GameConnection.on(event)

    async def verify_email(self, username: str, token: str):
        """Verify an email address."""
        url = self.url + '/accounts/verify_email'
        params = {'username': username, 'token': token}
        async with self.aiohttp_session.get(url, params=params) as resp:
            self._handle_response(resp)


class Session:
    """An authenticated session."""

    def __init__(self, client: Client, token: str, session_id: str):
        """Start the session."""
        self.token = token
        self.id = session_id
        self.client = client
        self.user = None

    async def _get_authenticated(
            self, endpoint: str, payload: Json = None,
            method: str = 'GET') -> Json:
        """Get an endpoint that requires authentication."""
        payload = payload or {}    # Avoid mutable parameter default.
        payload['session_id'] = self.id
        payload['session_token'] = self.token
        method = {
            'GET': self.client.aiohttp_session.get,
            'DELETE': self.client.aiohttp_session.delete
        }[method]
        async with method(self.client.url + endpoint, params=payload) as resp:
            return self.client._handle_response(resp)

    async def _post_authenticated(
            self, endpoint: str, payload: Json,
            method: str = 'POST', encrypted: bool = False) -> Json:
        """Post to an endpoint that requires authentication."""
        payload['session_id'] = self.id
        payload['session_token'] = self.token
        return await self.client._post_payload(
            endpoint, payload, method, encrypted
        )

    async def logout(self):
        """End the session."""
        await self._get_authenticated('/accounts/logout')

    async def resend_verification_email(self):
        """Resend the verification email for an account."""
        await self._get_authenticated('/accounts/resend_verification_email')

    async def update(self, password: str = None, email: str = None):
        """Update the user's account."""
        payload = {}
        if password:
            payload['password'] = password
        if email:
            payload['email'] = email
        self.user = None
        await self._post_authenticated('/accounts/me', payload, 'PATCH', True)

    async def fetch_user(self) -> User:
        """Get the user's account details."""
        details = self._get_authenticated('/accounts/me')
        self.user = User(self.client, details)
        return self.user

    async def get_user(self) -> User:
        """Get the cached user, or fetch if not cached (recommended)."""
        return self.user or await self.fetch_user()

    async def delete(self):
        """Delete the user's account."""
        await self._get_authenticated('/accounts/me', method='DELETE')

    def _get_games_paginator(
            self, endpoint: str, start_page: int,
            **params: Json) -> Paginator:
        """Get a paginated list of games."""
        params['session_id'] = self.id
        params['session_token'] = self.token
        return Paginator(
            client=self.client,
            endpoint='/games/' + endpoint,
            main_field='games',
            model=Game,
            start_page=start_page,
            params=params,
            reference_fields={
                'host': 'users', 'away': 'users', 'invited': 'users'
            }
        )

    def get_common_completed_games(
            self, other: User, start_page: int = 0) -> Paginator:
        """Get a list of games this user has in common with someone else."""
        return self._get_games_paginator(
            'common_completed', start_page, account=other.username
        )

    def get_invites(self, start_page: int = 0) -> Paginator:
        """Get a list of games this user has been invited to."""
        return self._get_games_paginator('invites', start_page)

    def get_searches(self, start_page: int = 0) -> Paginator:
        """Get a list of outgoing game searches this user has."""
        return self._get_games_paginator('searches', start_page)

    def get_ongoing(self, start_page: int = 0) -> Paginator:
        """Get a list of ongoing games this user is in."""
        return self._get_games_paginator('ongoing', start_page)

    async def find_game(
            self,
            main_thinking_time: datetime.timedelta,
            fixed_extra_time: datetime.timedelta,
            time_increment_per_turn: datetime.timedelta,
            mode: Gamemode) -> Game:
        """Look for or create a game."""
        response = await self._post_authenticated(
            '/games/find', {
                'main_thinking_time': dump_timedelta(main_thinking_time),
                'fixed_extra_time': dump_timedelta(fixed_extra_time),
                'time_increment_per_turn': dump_timedelta(
                    time_increment_per_turn
                ),
                'mode': mode.value
            }
        )
        return await self.client.get_game(response['game_id'])

    async def send_invitation(
            self, other: User,
            main_thinking_time: datetime.timedelta,
            fixed_extra_time: datetime.timedelta,
            time_increment_per_turn: datetime.timedelta,
            mode: Gamemode) -> Game:
        """Send an invitation to another user."""
        response = await self._post_authenticated(
            '/games/send_invitation', {
                'invitee': other.username,
                'main_thinking_time': dump_timedelta(main_thinking_time),
                'fixed_extra_time': dump_timedelta(fixed_extra_time),
                'time_increment_per_turn': dump_timedelta(
                    time_increment_per_turn
                ),
                'mode': mode.value
            }
        )
        return await self.client.get_game(response['game_id'])

    async def accept_invitation(self, invitation: Game):
        """Accept a game you have been invited to."""
        await self._post_authenticated(
            '/games/invites/' + str(invitation.id), {}
        )

    async def decline_invitation(self, invitation: Game):
        """Decline a game you have been invited to."""
        await self._get_authenticated(
            '/games/invites/' + str(invitation.id), method='DELETE'
        )

    async def connect_to_game(self, game: Game) -> GameConnection:
        """Connect to a websocket for a game."""
        connection = GameConnection(self, game)
        await connection.connect()
        return connection


class GameConnection(socketio.AsyncClient):
    """A websocket connection for a game."""

    _connections = []
    handlers = collections.defaultdict(list)

    @classmethod
    def on(cls, event: Event) -> typing.Callable:
        """Generate a wrapper for adding an event handler."""
        def wrapper(callback: typing.Awaitable) -> typing.Awaitable:
            """Wrap a function to add an event handler."""
            cls.handlers[event].append(callback)
            return callback
        return wrapper

    @classmethod
    async def dispatch(
            cls, event: Event, instance: GameConnection,
            *args: typing.Tuple[typing.Any]):
        """Dispatch an event to registered handlers."""
        for handler in cls.handlers[event]:
            await handler(instance, *args)

    def __init__(self, session: Session, game: Game):
        """Connect to the game."""
        super().__init__()
        self.session = session
        self.client = session.client
        self.game_id = game.id
        self.disconnect_reason = None
        self.game_end_reason = None
        self.game = game
        self.board = None
        self.timer = None
        self.current_turn = None
        self.turn_number = None
        self.allowed_moves = None
        self.valid_draw_claim = None

        super().on('game_disconnect', self.game_disconnect_event)
        super().on('game_start', self.game_start_event)
        super().on('game_end', self.game_end_event)
        super().on('draw_offer', self.draw_offer_event)
        super().on('move', self.move_event)
        super().on('game_state', self.game_state_event)
        super().on('allowed_moves', self.allowed_moves_event)
        super().on('bad_request', self.on_error)

        super().on('connect', self.on_connect)
        super().on('disconnect', self.on_disconnect)

    async def connect(self):
        """Connect to the server."""
        session_token = base64.b64encode(self.session.token)
        headers = {
            'Game-ID': self.game_id,
            'Authorization': f'SessionKey {self.session.id}|{session_token}'
        }
        await super().connect(self.client.url, headers=headers)

    async def on_connect(self):
        """Add this instance to the list of connections."""
        type(self)._connections.append(self)

    async def on_disconnect(self):
        """Remove this instance from the list of connections."""
        if self in type(self)._connections:
            type(self)._connections.remove(self)

    async def fetch_game(self) -> Game:
        """Fetch the game associated with this socket."""
        self.game = await self.client.get_game(self.game_id)
        return self.game

    async def get_game(self) -> Game:
        """Get the cached game if it's cached or fetch if not."""
        return self.game or await self.fetch_game()

    async def request_game_state(self):
        """Request the current state of the game."""
        await self.emit('game_state')

    def get_game_state(self):
        """Request and wait for the current state of the game (blocking)."""
        self.call('game_state')

    async def request_allowed_moves(self):
        """Request the moves we are allowed to make."""
        await self.emit('allowed_moves')

    def get_allowed_moves(self):
        """Request and wait for valid moves (blocking)."""
        self.call('allowed_moves')

    async def make_move(self, move: Move):
        """Make a move."""
        await self.emit('move', move.to_json())

    async def offer_draw(self):
        """Offer our opponent a draw."""
        await self.emit('offer_draw')

    async def claim_draw(self, reason: Conclusion):
        """Claim a draw."""
        await self.emit('claim_draw', reason.value)

    async def resign(self):
        """Resign from the game."""
        await self.emit('resign')

    def _load_game_state(
            self, board: Json, home_time: int, away_time: int, last_turn: int,
            current_turn: int, turn_number: int):
        """Load the current state of the game."""
        self.board = Board(board)
        self.timer = Timer(home_time, away_time, last_turn)
        self.current_turn = Side(current_turn)
        self.turn_number = turn_number

    def _load_allowed_moves(
            self, moves: typing.List[Json], draw_claim: typing.Optional[int]):
        """Load allowed moves."""
        self.allowed_moves = [
            self.game.mode.move_class(**args) for args in moves
        ]
        self.valid_draw_claim = Conclusion(draw_claim) if draw_claim else None

    async def game_disconnect_event(self, reason: int):
        """Handle an event indicating that we will be disconnected."""
        self.disconnect_reason = DisconnectReason(reason)
        await type(self).dispatch(
            Event.DISCONNECT, self, self.disconnect_reason
        )

    async def game_start_event(self):
        """Handle the game starting."""
        self.game = None
        await type(self).dispatch(Event.GAME_START, self)

    async def game_end_event(self, game_state: Json, reason: int):
        """Handle the game ending."""
        self.game = None
        self.game_end_reason = Conclusion(reason)
        self._load_game_state(**game_state)
        await type(self).dispatch(Event.GAME_END, self, self.game_end_reason)

    async def draw_offer_event(self):
        """Handle a draw being offered."""
        self.game = None
        await type(self).dispatch(Event.DRAW_OFFER, self)

    async def move_event(
            self, move: Json, game_state: Json, allowed_moves: Json):
        """Handle our opponent making a move."""
        move = self.game.move_class(move)
        self._load_game_state(**game_state)
        self._load_allowed_moves(**allowed_moves)
        await type(self).dispatch(
            Event.MOVE, self, move, self.allowed_moves, self.valid_draw_claim
        )

    async def game_state_event(self, **game_state: Json):
        """Handle the game state being sent."""
        self._load_game_state(**game_state)

    async def allowed_moves_event(self, **allowed_moves: Json):
        """Handle the allowed moves being sent."""
        self._load_allowed_moves(**allowed_moves)

    async def on_error(self, **error: Json):
        """Handle an error being returned by the server."""
        raise RequestError(error)


class User:
    """A user from the API."""

    def __init__(self, client: Client, data: Json):
        """Load the user attributes."""
        self.client = client
        self.id = data['id']
        self.username = data['username']
        self.elo = data['elo']
        self.created_at = load_timestamp(data['created_at'])
        if 'email' in data:
            # If this is was fetched as the currently authenticated user.
            self.email = data['email']
            self.authenticated = True
        else:
            self.authenticated = False

    def get_completed_games(self) -> Paginator:
        """Get a paginated list of games this user has completed."""
        return Paginator(
            client=self.client,
            endpoint='/games/completed',
            main_field='games',
            model=Game,
            params={'account': self.username},
            reference_fields={
                'host': 'users', 'away': 'users', 'invited': 'users'
            }
        )

    def __eq__(self, other: User) -> bool:
        """Check if another instance refers to the same user."""
        return isinstance(other, User) and other.id == self.id


class Game:
    """A game from the API."""

    def __init__(self, client: Client, data: Json):
        """Load the game attributes."""
        self.client = client
        self.id = data['id']
        self.mode = Gamemode(data['mode'])
        self.host = User(client, data['host']) if data['host'] else None
        self.away = User(client, data['away']) if data['away'] else None
        self.invited = (
            User(client, data['invited']) if data['invited'] else None
        )
        self.current_turn = Side(data['current_turn'])
        self.turn_number = data['turn_number']
        self.main_thinking_time = load_timedelta(data['main_thinking_time'])
        self.fixed_extra_time = load_timedelta(data['fixed_extra_time'])
        self.time_increment_per_turn = load_timedelta(
            data['time_increment_per_turn']
        )
        self.home_time = load_timedelta(data['home_time'])
        self.away_time = load_timedelta(data['away_time'])
        self.home_offering_draw = data['home_offering_draw']
        self.away_offering_draw = data['away_offering_draw']
        self.winner = Winner(data['winner'])
        self.conclusion_type = Conclusion(data['conclusion_type'])
        self.opened_at = load_timestamp(data['opened_at'])
        self.started_at = load_timestamp(data['started_at'])
        self.last_turn = load_timestamp(data['last_turn'])
        self.ended_at = load_timestamp(data['ended_at'])

    def __eq__(self, other: Game) -> bool:
        """Check if another instance refers to the same game."""
        return isinstance(other, Game) and other.id == self.id


class Paginator:
    """A paginated list of entities from the API."""

    def __init__(
            self, client: Client, endpoint: str, main_field: str,
            model: typing.Any, start_page: int = 0, params: Json = None,
            reference_fields: typing.Dict[str, str] = None):
        """Initialise the paginator."""
        self.client = client
        self._page = None
        self.page_number = start_page
        self.pages = None
        self._index = 0
        self.per_page = 100
        self._endpoint = endpoint
        self._params = params or {}
        self._main_field = main_field
        self._reference_fields = reference_fields or {}
        self._model = model

    async def _get_page(self):
        """Fetch the current page."""
        self._params['page'] = self.page_number
        request = self.client.aiohttp_session.get(
            self.client.url + self._endpoint, params=self._params
        )
        async with request as resp:
            raw = self.client._handle_response(resp)
        self.pages = raw['pages']
        self._page = []
        for data in raw[self._main_field]:
            for field in data:
                if field in self._reference_fields:
                    if data[field]:
                        data[field] = raw[
                            self._reference_fields[field]
                        ][str(data[field])]
            self._page.append(self._model(self.client, data))

    async def __aiter__(self) -> Paginator:
        """Initialise this as an iterable."""
        self._index = 0
        await self._get_page()
        self.per_page = len(self._page)
        return self

    async def __anext__(self) -> User:
        """Get the next item."""
        if self._index < len(self._page):
            value = self._page[self._index]
            self._index += 1
            return value
        elif self.page_number + 1 < self.pages:
            self.page_number += 1
            await self._get_page()
            self._index = 1
            return self._page[0]
        else:
            raise StopIteration

    def __len__(self) -> int:
        """Calculate an approximate for the number of items."""
        return self.pages * self.per_page


class Board:
    """A class representing the current state of a board."""

    Square = collections.namedtuple('Square', ['piece', 'side'])

    def __init__(self, raw_data: Json):
        """Load the raw data."""
        self.squares = {}
        for position in raw_data:
            rank, file = raw_data.split(',')
            raw_piece, raw_side = raw_data[position]
            square = self.Square(Piece(raw_piece), Side(raw_side))
            self.squares[rank, file] = square

    def __getitem__(self, position: typing.Tuple) -> Board.Square:
        """Get a square by rank and file."""
        return self.squares[position]


class Timer:
    """A class representing the clocks in a game."""

    def __init__(self, home_time: int, away_time: int, last_turn: int):
        """Load the current times."""
        self.last_turn = load_timestamp(last_turn)
        self.home_time_last = load_timedelta(home_time)
        self.away_time_last = load_timedelta(away_time)

    @property
    def home_time(self) -> datetime.timedelta:
        """Get the actual home time."""
        return self.home_time_last + self.last_turn - datetime.datetime.now()

    @property
    def away_time(self) -> datetime.timedelta:
        """Get the actual away time."""
        return self.away_time_last + self.last_turn - datetime.datetime.now()


class Move:
    """A class representing a move being made in some gamemode."""

    @classmethod
    def from_json(cls, **data: Json) -> Move:
        """Load a move from raw values."""
        raise NotImplementedError('This should be implemented in subclasses.')

    def __init__(self, **data: Json):
        """Store associated data."""
        raise NotImplementedError('This should be implemented in subclasses.')

    def to_json(self) -> Json:
        """Convert to a JSON-serialisable dict."""
        raise NotImplementedError('This should be implemented in subclasses.')


class ChessMove(Move):
    """A class representing a move in chess."""

    @classmethod
    def from_json(
            cls, start_rank: int, start_file: int, end_rank: int,
            end_file: int, promotion: typing.Optional[int]) -> ChessMove:
        """Load a move from raw values."""
        if promotion:
            promotion = Piece(promotion)
        return cls(start_rank, start_file, end_rank, end_file, promotion)

    def __init__(
            self, start_rank: int, start_file: int, end_rank: int,
            end_file: int, promotion: typing.Optional[Piece]):
        """Store associated data."""
        super().__init__()
        self.start_rank = start_rank
        self.start_file = start_file
        self.end_rank = end_rank
        self.end_file = end_file
        self.promotion = promotion

    def to_json(self) -> Json:
        """Convert to a JSON-serialisable dict."""
        return {
            'start_rank': self.start_rank,
            'start_file': self.start_file,
            'end_rank': self.end_rank,
            'end_file': self.end_file,
            'promotion': self.promotion.value if self.promotion else None
        }
