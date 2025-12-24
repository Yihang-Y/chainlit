import asyncio
import json
from typing import Any, Dict, Literal, Optional, Tuple, TypedDict, Union
from urllib.parse import unquote

from starlette.requests import cookie_parser
from typing_extensions import TypeAlias

from chainlit.auth import (
    get_current_user,
    get_token_from_cookies,
    require_login,
)
from chainlit.chat_context import chat_context
from chainlit.config import ChainlitConfig, config
from chainlit.context import init_ws_context
from chainlit.data import get_data_layer
from chainlit.logger import logger
from chainlit.message import ErrorMessage, Message
from chainlit.server import sio
from chainlit.session import ClientType, WebsocketSession
from chainlit.types import (
    InputAudioChunk,
    InputAudioChunkPayload,
    MessagePayload,
)
from chainlit.user import PersistedUser, User
from chainlit.user_session import user_sessions

WSGIEnvironment: TypeAlias = dict[str, Any]


class WebSocketSessionAuth(TypedDict):
    sessionId: str
    userEnv: str | None
    clientType: ClientType
    chatProfile: str | None
    threadId: str | None


def restore_existing_session(sid, session_id, emit_fn, emit_call_fn, environ):
    """Restore a session from the sessionId provided by the client."""
    if session := WebsocketSession.get_by_id(session_id):
        session.restore(new_socket_id=sid)
        session.emit = emit_fn
        session.emit_call = emit_call_fn
        session.environ = environ
        return True
    return False


async def persist_user_session(thread_id: str, metadata: Dict):
    if data_layer := get_data_layer():
        await data_layer.update_thread(thread_id=thread_id, metadata=metadata)


async def resume_thread(session: WebsocketSession):
    data_layer = get_data_layer()
    if not data_layer or not session.user or not session.thread_id_to_resume:
        return
    thread = await data_layer.get_thread(thread_id=session.thread_id_to_resume)
    if not thread:
        return

    author = thread.get("userIdentifier")
    user_is_author = author == session.user.identifier

    if user_is_author:
        metadata = thread.get("metadata") or {}
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        user_sessions[session.id] = metadata.copy()
        if chat_profile := metadata.get("chat_profile"):
            session.chat_profile = chat_profile
        if chat_settings := metadata.get("chat_settings"):
            session.chat_settings = chat_settings

        return thread


def load_user_env(user_env):
    if user_env:
        user_env_dict = json.loads(user_env)
    # Check user env
    if config.project.user_env:
        if not user_env_dict:
            raise ConnectionRefusedError("Missing user environment variables")
        # Check if requested user environment variables are provided
        for key in config.project.user_env:
            if key not in user_env_dict:
                raise ConnectionRefusedError(
                    "Missing user environment variable: " + key
                )
    return user_env_dict


def _get_token_from_cookie(environ: WSGIEnvironment) -> Optional[str]:
    if cookie_header := environ.get("HTTP_COOKIE", None):
        cookies = cookie_parser(cookie_header)
        return get_token_from_cookies(cookies)

    return None


def _get_token(environ: WSGIEnvironment) -> Optional[str]:
    """Take WSGI environ, return access token."""
    return _get_token_from_cookie(environ)


async def _authenticate_connection(
    environ: WSGIEnvironment,
) -> Union[Tuple[Union[User, PersistedUser], str], Tuple[None, None]]:
    if token := _get_token(environ):
        user = await get_current_user(token=token)
        if user:
            return user, token

    return None, None


@sio.on("connect")  # pyright: ignore [reportOptionalCall]
async def connect(sid: str, environ: WSGIEnvironment, auth: WebSocketSessionAuth):
    user: User | PersistedUser | None = None
    token: str | None = None
    thread_id = auth.get("threadId", None)

    if require_login():
        try:
            user, token = await _authenticate_connection(environ)
        except Exception as e:
            logger.exception("Exception authenticating connection: %s", e)

        if not user:
            logger.error("Authentication failed in websocket connect.")
            raise ConnectionRefusedError("authentication failed")

        if thread_id:
            if data_layer := get_data_layer():
                thread = await data_layer.get_thread(thread_id)
                if thread and not (thread["userIdentifier"] == user.identifier):
                    logger.error("Authorization for the thread failed.")
                    raise ConnectionRefusedError("authorization failed")

    # Session scoped function to emit to the client
    def emit_fn(event, data):
        return sio.emit(event, data, to=sid)

    # Session scoped function to emit to the client and wait for a response
    def emit_call_fn(event: Literal["ask", "call_fn"], data, timeout):
        return sio.call(event, data, timeout=timeout, to=sid)

    session_id = auth["sessionId"]
    if restore_existing_session(sid, session_id, emit_fn, emit_call_fn, environ):
        return True

    user_env_string = auth.get("userEnv", None)
    user_env = load_user_env(user_env_string)

    client_type = auth["clientType"]
    url_encoded_chat_profile = auth.get("chatProfile", None)
    chat_profile = (
        unquote(url_encoded_chat_profile) if url_encoded_chat_profile else None
    )

    WebsocketSession(
        id=session_id,
        socket_id=sid,
        emit=emit_fn,
        emit_call=emit_call_fn,
        client_type=client_type,
        user_env=user_env,
        user=user,
        token=token,
        chat_profile=chat_profile,
        thread_id=thread_id,
        environ=environ,
    )

    return True


@sio.on("connection_successful")  # pyright: ignore [reportOptionalCall]
async def connection_successful(sid):
    context = init_ws_context(sid)

    await context.emitter.task_end()
    await context.emitter.clear("clear_ask")
    await context.emitter.clear("clear_call_fn")

    if context.session.restored and not context.session.has_first_interaction:
        if config.code.on_chat_start:
            task = asyncio.create_task(config.code.on_chat_start())
            context.session.current_task = task
        return

    if context.session.thread_id_to_resume and config.code.on_chat_resume:
        thread = await resume_thread(context.session)
        if thread:
            context.session.has_first_interaction = True
            await context.emitter.emit(
                "first_interaction",
                {"interaction": "resume", "thread_id": thread.get("id")},
            )
            await config.code.on_chat_resume(thread)

            for step in thread.get("steps", []):
                if "message" in step["type"]:
                    chat_context.add(Message.from_dict(step))

            await context.emitter.resume_thread(thread)
            return
        else:
            await context.emitter.send_resume_thread_error("Thread not found.")

    if config.code.on_chat_start:
        task = asyncio.create_task(config.code.on_chat_start())
        context.session.current_task = task


@sio.on("clear_session")  # pyright: ignore [reportOptionalCall]
async def clean_session(sid):
    session = WebsocketSession.get(sid)
    if session:
        session.to_clear = True


@sio.on("disconnect")  # pyright: ignore [reportOptionalCall]
async def disconnect(sid):
    session = WebsocketSession.get(sid)

    if not session:
        return

    init_ws_context(session)

    if config.code.on_chat_end:
        await config.code.on_chat_end()

    if session.thread_id and session.has_first_interaction:
        await persist_user_session(session.thread_id, session.to_persistable())

    async def clear(_sid):
        if session := WebsocketSession.get(_sid):
            # Clean up the user session
            if session.id in user_sessions:
                user_sessions.pop(session.id)
            # Clean up the session
            await session.delete()

    if session.to_clear:
        await clear(sid)
    else:

        async def clear_on_timeout(_sid):
            await asyncio.sleep(config.project.session_timeout)
            await clear(_sid)

        asyncio.ensure_future(clear_on_timeout(sid))


@sio.on("stop")  # pyright: ignore [reportOptionalCall]
async def stop(sid):
    if session := WebsocketSession.get(sid):
        init_ws_context(session)
        await Message(content="Task manually stopped.").send()

        if session.current_task:
            session.current_task.cancel()

        if config.code.on_stop:
            await config.code.on_stop()


async def process_message(session: WebsocketSession, payload: MessagePayload):
    """Process a message from the user."""
    try:
        context = init_ws_context(session)
        await context.emitter.task_start()
        message = await context.emitter.process_message(payload)

        if config.code.on_message:
            await asyncio.sleep(0.001)
            await config.code.on_message(message)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.exception(e)
        await ErrorMessage(
            author="Error", content=str(e) or e.__class__.__name__
        ).send()
    finally:
        await context.emitter.task_end()


async def fetch_steps(data_layer, thread_id: str):
    from sqlalchemy import text
    sql = text("""
        SELECT
            s."id"       AS step_id,
            s."name"     AS step_name,
            s."parentId" AS step_parentid,
            s."input"    AS step_input,
            s."output"   AS step_output
        FROM steps s
        WHERE s."threadId" = :thread_id
        ORDER BY s."createdAt" ASC
    """)

    async with data_layer.async_session() as session:
        result = await session.execute(sql, {"thread_id": thread_id})
        rows = result.mappings().all()
        return rows

@sio.on("edit_message")  
async def edit_message(sid, payload: MessagePayload):
    from chainlit.step import Step

    session = WebsocketSession.require(sid)  
    context = init_ws_context(session)  
  
    messages = chat_context.get()
    if messages is None:
        logger.error("No messages found in chat context.")
        return
    print("messages ids:", [m.id for m in messages if m])
    steps_data = await fetch_steps(get_data_layer(), session.thread_id)
    
    # Message or Step id that has been edited
    target_id = str(payload["message"]["id"])
    # edited content
    new_output = payload["message"].get("output")
    message_type = payload["message"].get("type")  
    
    # try to locate the edited one by matching messages
    orig_message = None  
    original_content = "" 
    
    remove_messages = []
    found = False 
    for message in messages:  
        if not message:  
            continue
        
        if found:
            remove_messages.append(message)
            continue
    
        if str(message.id) == target_id:  
            found = True
            orig_message = message
            original_content = message.content or ""
            
            if new_output is None:
                logger.error("No new output provided for edited message.")
                return
            message.content = new_output
            
            message.metadata = message.metadata or {}
            message.metadata["edited"] = True
            message.metadata["original_content"] = original_content
            await message.update()
            
    for m in remove_messages:
        # chat_context.remove(m)
        await m.remove()
    
    print(payload["message"])
    if not found:
        new_input = payload["message"].get("input")
        new_output = payload["message"].get("output")
        
        orig_step = None
        step_original_content = ""
        
        remove_steps = []
        found_step = False
        
        for s in steps_data:
            step_id = str(s.get("step_id"))
            step = Step(id=step_id, name=s.get("step_name"))
            step.parent_id = str(s.get("step_parentid"))
            
            if found_step:
                remove_steps.append(step)
                continue
            
            if step_id == target_id:
                logger.info(f"Found edited step: {step_id}")
                found_step = True
                orig_step = step
                step_original_input = s.get("step_input")
                step_original_output = s.get("step_output") 
                
                # judge whether input or output is edited
                if new_input is not None and new_input != step_original_input:
                    step_original_content = step_original_input or ""
                    step.input = new_input
                    step.output = None  # clear output if input is changed
                elif new_output is not None and new_output != step_original_output:
                    step_original_content = step_original_output or ""
                    step.input = step_original_input
                    step.output = new_output
                else:
                    logger.error("No changes detected in input or output.")
                    logger.info(f"Original input: {step_original_input}, New input: {new_input}")
                    logger.info(f"Original output: {step_original_output}, New output: {new_output}")
                    break
            
                    
                await step.update()

        for s in remove_steps:
            await s.remove()
            
        # if not original_content:
        original_content = step_original_content
        if not step_original_content:
            logger.error("Original content not found in step.")
            return
        
        if orig_message is None:
            orig_message = Message(content="")
            orig_message.metadata = {}
            orig_message.metadata["edited"] = True
            orig_message.metadata["original_content"] = original_content
            orig_message.metadata["edit_step"] = True
            orig_message.metadata["edited_step_id"] = str(orig_step.id)
            orig_message.metadata["type"] = message_type
            
    await context.emitter.task_start()  
  
    if config.code.on_message:  
        try:  
            await config.code.on_message(orig_message)  
        except asyncio.CancelledError:  
            pass  
        finally:  
            await context.emitter.task_end()


@sio.on("client_message")  # pyright: ignore [reportOptionalCall]
async def message(sid, payload: MessagePayload):
    """Handle a message sent by the User."""
    session = WebsocketSession.require(sid)

    task = asyncio.create_task(process_message(session, payload))
    session.current_task = task


@sio.on("window_message")  # pyright: ignore [reportOptionalCall]
async def window_message(sid, data):
    """Handle a message send by the host window."""
    session = WebsocketSession.require(sid)
    init_ws_context(session)

    if config.code.on_window_message:
        try:
            await config.code.on_window_message(data)
        except asyncio.CancelledError:
            pass


@sio.on("audio_start")  # pyright: ignore [reportOptionalCall]
async def audio_start(sid):
    """Handle audio init."""
    session = WebsocketSession.require(sid)

    context = init_ws_context(session)
    config: ChainlitConfig = session.get_config()  # type: ignore

    if config.features.audio and config.features.audio.enabled:
        connected = bool(await config.code.on_audio_start())
        connection_state = "on" if connected else "off"
        await context.emitter.update_audio_connection(connection_state)


@sio.on("audio_chunk")
async def audio_chunk(sid, payload: InputAudioChunkPayload):
    """Handle an audio chunk sent by the user."""
    session = WebsocketSession.require(sid)

    init_ws_context(session)

    config: ChainlitConfig = session.get_config()

    if (
        config.features.audio
        and config.features.audio.enabled
        and config.code.on_audio_chunk
    ):
        asyncio.create_task(config.code.on_audio_chunk(InputAudioChunk(**payload)))


@sio.on("audio_end")
async def audio_end(sid):
    """Handle the end of the audio stream."""
    session = WebsocketSession.require(sid)

    try:
        context = init_ws_context(session)
        await context.emitter.task_start()

        if not session.has_first_interaction:
            session.has_first_interaction = True
            asyncio.create_task(context.emitter.init_thread("audio"))

        config: ChainlitConfig = session.get_config()  # type: ignore

        if config.features.audio and config.features.audio.enabled:
            await config.code.on_audio_end()

    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.exception(e)
        await ErrorMessage(
            author="Error", content=str(e) or e.__class__.__name__
        ).send()
    finally:
        await context.emitter.task_end()


@sio.on("chat_settings_change")
async def change_settings(sid, settings: Dict[str, Any]):
    """Handle change settings submit from the UI."""
    context = init_ws_context(sid)

    for key, value in settings.items():
        context.session.chat_settings[key] = value

    if config.code.on_settings_update:
        await config.code.on_settings_update(settings)
