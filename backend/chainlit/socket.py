import asyncio
import inspect
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


async def restore_existing_session(sid, session_id, emit_fn, emit_call_fn, environ):
    """Restore a session from the sessionId provided by the client."""
    logger.info(f"[RESTORE] Attempting to restore session_id={session_id} with new sid={sid}")
    if session := WebsocketSession.get_by_id(session_id):
        old_socket_id = session.socket_id
        logger.info(f"[RESTORE] Found existing session: session_id={session_id}, old_socket_id={old_socket_id}, new_sid={sid}, has_first_interaction={session.has_first_interaction}, thread_id={session.thread_id}")
        
        # Cancel old clear_task if it exists (to prevent cleanup with old sid)
        user_session = user_sessions.get(session_id)
        if isinstance(user_session, dict):
            old_clear_task = user_session.get("clear_task")
            if old_clear_task and not old_clear_task.done():
                logger.info(f"[RESTORE] Cancelling old clear_task for session {session_id}")
                old_clear_task.cancel()
                # Wait for the task to be cancelled (but don't wait too long)
                try:
                    await asyncio.wait_for(old_clear_task, timeout=0.1)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass
                except Exception as e:
                    logger.debug(f"Error waiting for clear_task cancellation: {e}")
        
        # Disconnect the old socket connection if it's different from the new one
        if old_socket_id != sid:
            logger.info(f"[RESTORE] Disconnecting old socket {old_socket_id} for session {session_id}, new socket is {sid}")
            try:
                # Disconnect the old socket to prevent duplicate connections
                # Note: sio.disconnect() is synchronous but we're in an async context
                await sio.disconnect(old_socket_id)
                logger.info(f"[RESTORE] Successfully disconnected old socket {old_socket_id}")
            except Exception as e:
                logger.warning(f"[RESTORE] Error disconnecting old socket {old_socket_id}: {e}")
        
        session.restore(new_socket_id=sid)
        session.emit = emit_fn
        session.emit_call = emit_call_fn
        session.environ = environ
        logger.info(f"[RESTORE] Successfully restored session {session_id}, new socket_id={sid}")
        return True
    logger.info(f"[RESTORE] No existing session found for session_id={session_id}")
    return False


async def persist_user_session(thread_id: str, metadata: Dict):
    if data_layer := get_data_layer():
        await data_layer.update_thread(thread_id=thread_id, metadata=metadata)


async def resume_thread(session: WebsocketSession):
    print(f"Resuming thread {session.thread_id_to_resume}")
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
        
        # Create a clean copy of metadata, excluding resource objects
        # Only copy serializable data to avoid resource management issues
        # 
        # Why update user_sessions here?
        # - When a session disconnects, user_sessions[session.id] is saved to thread.metadata via session.to_persistable()
        # - When resuming a thread, we need to restore this data back to user_sessions[session.id]
        # - This allows cl.user_session.get() to access the restored data (e.g., profile, chat_settings)
        clean_metadata = {}
        for key, value in metadata.items():
            # Skip resource objects that shouldn't be copied
            # These are managed separately in cl.user_session (e.g., mcp_session, mcp_tools)
            if key in ["mcp_session", "mcp_tools"]:
                continue
            # Only copy serializable values (dict, list, str, int, float, bool, None)
            if isinstance(value, (dict, list, str, int, float, bool, type(None))):
                clean_metadata[key] = value
            elif isinstance(value, list):
                # For lists, only copy serializable items
                clean_metadata[key] = [
                    item for item in value 
                    if isinstance(item, (dict, list, str, int, float, bool, type(None)))
                ]
        
        # Only update user_sessions if clean_metadata is not empty
        # Update existing dict instead of replacing to avoid triggering cleanup of old resources
        if clean_metadata:
            try:
                # Get or create session dict
                if session.id not in user_sessions:
                    user_sessions[session.id] = {}
                
                # Update existing dict instead of replacing to avoid triggering resource cleanup
                existing_session = user_sessions[session.id]
                if isinstance(existing_session, dict):
                    # Safe cleanup of mcp resources if they exist
                    # Use marking + _close_mcp_session_if_needed to avoid RuntimeError
                    if "mcp_session" in existing_session:
                        logger.info(f"[RESUME] Marking mcp_session for closure for session {session.id}")
                        existing_session["mcp_should_close"] = True
                        await _close_mcp_session_if_needed(session.id)
                    
                    # Ensure mcp_tools is also cleared if it wasn't by _close_mcp_session_if_needed
                    existing_session.pop("mcp_tools", None)
                    
                    # Update with clean metadata
                    existing_session.update(clean_metadata)
                else:
                    # If existing_session is not a dict, replace it
                    user_sessions[session.id] = clean_metadata
            except RuntimeError as e:
                # Ignore RuntimeError from async generator cleanup
                # This can happen when the session is being cleaned up
                logger.debug(f"Could not update user_sessions (session may be closing): {e}")
            except Exception as e:
                # Catch any other exceptions during cleanup
                logger.debug(f"Error updating user_sessions: {e}")
        
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
    logger.info(f"[CONNECT] New connection: sid={sid}, session_id={auth.get('sessionId')}, thread_id={auth.get('threadId')}")
    user: User | PersistedUser | None = None
    token: str | None = None
    thread_id = auth.get("threadId", None)

    if require_login():
        try:
            user, token = await _authenticate_connection(environ)
            logger.info(f"[CONNECT] Authentication successful: user={user.identifier if user else None}")
        except Exception as e:
            logger.exception(f"[CONNECT] Exception authenticating connection: {e}")

        if not user:
            logger.error("[CONNECT] Authentication failed in websocket connect.")
            raise ConnectionRefusedError("authentication failed")

        if thread_id:
            if data_layer := get_data_layer():
                thread = await data_layer.get_thread(thread_id)
                if thread and not (thread["userIdentifier"] == user.identifier):
                    logger.error(f"[CONNECT] Authorization for the thread failed: thread_id={thread_id}, user={user.identifier}")
                    raise ConnectionRefusedError("authorization failed")

    # Session scoped function to emit to the client
    def emit_fn(event, data):
        return sio.emit(event, data, to=sid)

    # Session scoped function to emit to the client and wait for a response
    def emit_call_fn(event: Literal["ask", "call_fn"], data, timeout):
        return sio.call(event, data, timeout=timeout, to=sid)

    session_id = auth["sessionId"]
    logger.info(f"[CONNECT] Processing connection: sid={sid}, session_id={session_id}, thread_id={thread_id}")
    if await restore_existing_session(sid, session_id, emit_fn, emit_call_fn, environ):
        logger.info(f"[CONNECT] Session restored successfully: session_id={session_id}")
        return True

    # Check if a session with the same session_id already exists
    # This can happen if the client creates a new connection without properly disconnecting the old one
    existing_session = WebsocketSession.get_by_id(session_id)
    if existing_session:
        old_socket_id = existing_session.socket_id
        logger.warning(f"[CONNECT] Found existing session {session_id} with socket {old_socket_id}, disconnecting old socket before creating new session")
        try:
            # Disconnect the old socket to prevent duplicate connections
            await sio.disconnect(old_socket_id)
            logger.info(f"[CONNECT] Successfully disconnected old socket {old_socket_id}")
        except Exception as e:
            logger.warning(f"[CONNECT] Error disconnecting old socket {old_socket_id}: {e}")

    user_env_string = auth.get("userEnv", None)
    user_env = load_user_env(user_env_string)

    client_type = auth["clientType"]
    url_encoded_chat_profile = auth.get("chatProfile", None)
    chat_profile = (
        unquote(url_encoded_chat_profile) if url_encoded_chat_profile else None
    )

    logger.info(f"[CONNECT] Creating new session: session_id={session_id}, socket_id={sid}, client_type={client_type}, thread_id={thread_id}, chat_profile={chat_profile}")
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
    logger.info(f"[CONNECT] New session created successfully: session_id={session_id}, socket_id={sid}")
    return True


async def _close_mcp_session_if_needed(session_id: str):
    """
    Close mcp_session if mcp_should_close flag is set.
    This should be called in the same task chain where mcp_session was created
    (e.g., in on_chat_start, on_message callbacks).
    """
    logger.debug(f"[MCP_CLOSE] Checking if mcp_session needs to be closed for session {session_id}")
    user_session = user_sessions.get(session_id)
    if not isinstance(user_session, dict):
        logger.debug(f"[MCP_CLOSE] No user_session found for session {session_id}")
        return
    
    if not user_session.get("mcp_should_close"):
        logger.debug(f"[MCP_CLOSE] mcp_should_close flag not set for session {session_id}")
        return
    
    mcp_session = user_session.get("mcp_session")
    if mcp_session:
        logger.info(f"[MCP_CLOSE] Closing mcp_session for session {session_id} (flagged for closure)")
        try:
            if hasattr(mcp_session, "close"):
                if asyncio.iscoroutinefunction(mcp_session.close):
                    await mcp_session.close()
                else:
                    mcp_session.close()
                logger.info(f"[MCP_CLOSE] Successfully closed mcp_session using close() for session {session_id}")
            elif hasattr(mcp_session, "aclose"):
                if asyncio.iscoroutinefunction(mcp_session.aclose):
                    await mcp_session.aclose()
                else:
                    mcp_session.aclose()
                logger.info(f"[MCP_CLOSE] Successfully closed mcp_session using aclose() for session {session_id}")
        except Exception as e:
            logger.exception(f"[MCP_CLOSE] Error closing mcp_session for session {session_id}: {e}")
        finally:
            # Finalize: 清理标志和 mcp_session
            user_session.pop("mcp_session", None)
            user_session.pop("mcp_tools", None)
            user_session.pop("mcp_should_close", None)
            logger.info(f"[MCP_CLOSE] Cleaned up mcp_session, mcp_tools and flags for session {session_id}")
            
            # 如果 user_session 现在为空或只包含系统字段，可以完全删除
            # 保留一些系统字段（如 id, env 等）以便后续可能的使用
            remaining_keys = set(user_session.keys())
            system_keys = {"id", "env", "chat_settings", "user", "chat_profile", "client_type"}
            if not remaining_keys or remaining_keys.issubset(system_keys):
                user_sessions.pop(session_id, None)
                logger.debug(f"[MCP_CLOSE] Removed empty user_session for session {session_id}")
    else:
        logger.debug(f"[MCP_CLOSE] No mcp_session found in user_session for session {session_id}")


@sio.on("connection_successful")  # pyright: ignore [reportOptionalCall]
async def connection_successful(sid):
    logger.info(f"[CONN_SUCCESS] Connection successful: sid={sid}")
    import traceback
    context = init_ws_context(sid)
    logger.info(f"[CONN_SUCCESS] Session: session_id={context.session.id}, socket_id={context.session.socket_id}, restored={context.session.restored}, has_first_interaction={context.session.has_first_interaction}, thread_id={context.session.thread_id}, thread_id_to_resume={context.session.thread_id_to_resume}")

    # Clear ask and call_fn states on connection
    # Note: We don't send task_end here because there's no corresponding task_start
    # The frontend will reset loading counter on connect event
    await context.emitter.clear("clear_ask")
    await context.emitter.clear("clear_call_fn")

    # If session is restored (reconnected), check if it already has a thread_id
    # If it does, this means the conversation is already in progress, so skip on_chat_start
    if context.session.restored:
        logger.info(f"[CONN_SUCCESS] Session is restored")
        # If session already has first interaction or an active thread, skip on_chat_start
        # This prevents on_chat_start from being called during reconnects in the middle of a conversation
        if context.session.has_first_interaction or context.session.thread_id:
            logger.info(f"[CONN_SUCCESS] Skipping on_chat_start for restored session (has_first_interaction={context.session.has_first_interaction}, thread_id={context.session.thread_id})")
            return
        
        # Only call on_chat_start if this is a restored session that hasn't started yet
        if config.code.on_chat_start:
            logger.info(f"[CONN_SUCCESS] Calling on_chat_start for restored session (hasn't started yet)")
            # Close mcp_session if needed before calling on_chat_start
            await _close_mcp_session_if_needed(context.session.id)
            # Check if on_chat_start is already running to prevent duplicate calls
            if context.session.current_task and not context.session.current_task.done():
                logger.info(f"[CONN_SUCCESS] on_chat_start task already running, skipping duplicate call")
                return
            logger.info(f"[CONN_SUCCESS] Creating on_chat_start task")
            task = asyncio.create_task(config.code.on_chat_start())
            context.session.current_task = task
            logger.info(f"[CONN_SUCCESS] on_chat_start task created: {task}")
        else:
            logger.info(f"[CONN_SUCCESS] No on_chat_start callback configured")
        return

    if context.session.thread_id_to_resume and config.code.on_chat_resume:
        logger.info(f"[CONN_SUCCESS] Resuming thread: thread_id_to_resume={context.session.thread_id_to_resume}")
        thread = await resume_thread(context.session)
        if thread:
            context.session.has_first_interaction = True
            logger.info(f"[CONN_SUCCESS] Thread resumed successfully, calling on_chat_resume")
            await context.emitter.emit(
                "first_interaction",
                {"interaction": "resume", "thread_id": thread.get("id")},
            )
            await config.code.on_chat_resume(thread)

            for step in thread.get("steps", []):
                if "message" in step["type"]:
                    chat_context.add(Message.from_dict(step))

            await context.emitter.resume_thread(thread)
            logger.info(f"[CONN_SUCCESS] Thread resume completed")
            return
        else:
            logger.warning(f"[CONN_SUCCESS] Thread not found for resume: thread_id_to_resume={context.session.thread_id_to_resume}")
            await context.emitter.send_resume_thread_error("Thread not found.")

    # Only call on_chat_start if it hasn't been called yet for this session
    # This prevents duplicate calls on reconnects or multiple connection_successful events
    if config.code.on_chat_start:
        # Check if on_chat_start is already running to prevent duplicate calls
        if context.session.current_task and not context.session.current_task.done():
            logger.info(f"[CONN_SUCCESS] on_chat_start task already running, skipping duplicate call")
        elif context.session.has_first_interaction:
            logger.info(f"[CONN_SUCCESS] Skipping on_chat_start (has_first_interaction=True)")
        else:
            logger.info(f"[CONN_SUCCESS] Calling on_chat_start for new session (has_first_interaction={context.session.has_first_interaction})")
            # Close mcp_session if needed before calling on_chat_start
            await _close_mcp_session_if_needed(context.session.id)
            logger.info(f"[CONN_SUCCESS] Creating on_chat_start task")
            task = asyncio.create_task(config.code.on_chat_start())
            context.session.current_task = task
            logger.info(f"[CONN_SUCCESS] on_chat_start task created: {task}")
    else:
        logger.info(f"[CONN_SUCCESS] No on_chat_start callback configured")


@sio.on("clear_session")  # pyright: ignore [reportOptionalCall]
async def clean_session(sid):
    session = WebsocketSession.get(sid)
    if session:
        session.to_clear = True


@sio.on("disconnect")  # pyright: ignore [reportOptionalCall]
async def disconnect(sid):
    logger.info(f"[DISCONNECT] Disconnect event: sid={sid}")
    session = WebsocketSession.get(sid)
    logger.info(f"[DISCONNECT] Session lookup: sid={sid}, session_id={session.id if session else None}, socket_id={session.socket_id if session else None}")
    if not session:
        logger.warning(f"[DISCONNECT] No session found for sid={sid}")
        return

    logger.info(f"[DISCONNECT] Session details: session_id={session.id}, has_first_interaction={session.has_first_interaction}, thread_id={session.thread_id}, to_clear={session.to_clear}")
    init_ws_context(session)

    if config.code.on_chat_end:
        logger.info(f"[DISCONNECT] Calling on_chat_end for session {session.id}")
        await config.code.on_chat_end()

    if session.thread_id and session.has_first_interaction:
        logger.info(f"[DISCONNECT] Persisting user session: thread_id={session.thread_id}")
        await persist_user_session(session.thread_id, session.to_persistable())

    async def _maybe_await(x):
        if inspect.isawaitable(x):
            return await x
        return x

    async def _close_resource(resource, name: str):
        # 优先 aclose
        if hasattr(resource, "aclose"):
            try:
                return await _maybe_await(resource.aclose())
            except Exception:
                logger.exception(f"Error in {name}.aclose()")
                return

        # 再尝试 close
        if hasattr(resource, "close"):
            try:
                return await _maybe_await(resource.close())
            except Exception:
                logger.exception(f"Error in {name}.close()")
                return

    async def clear(_sid_or_session_id):
        """
        Clear a session by socket_id or session_id.
        If _sid_or_session_id is a socket_id, it will be used to find the session.
        If it's a session_id, it will be used directly.
        """
        # Try to get session by socket_id first
        session = WebsocketSession.get(_sid_or_session_id)
        if not session:
            # If not found by socket_id, try session_id
            session = WebsocketSession.get_by_id(_sid_or_session_id)
        
        if not session:
            logger.debug(f"Session not found for {_sid_or_session_id}, may have been already cleared")
            return

        logger.info(f"[CLEAR] Clearing session {session.id} (socket_id: {session.socket_id})")
        user_session = user_sessions.get(session.id)
        if isinstance(user_session, dict):
            logger.info(f"[CLEAR] Found user_session for session {session.id}, keys: {list(user_session.keys())}")
            # 1) 先取消 timeout task（避免重复 clear）
            t = user_session.get("clear_task")
            if t and t is not asyncio.current_task():
                logger.info(f"[CLEAR] Cancelling clear_task for session {session.id}")
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
                except Exception:
                    logger.exception("[CLEAR] clear_task exit error")
                user_session.pop("clear_task", None)

            # 2) 如果你有 reader/writer task，先 cancel 掉（示例）
            for k in ("mcp_reader_task", "mcp_writer_task"):
                task = user_session.get(k)
                if task:
                    logger.info(f"[CLEAR] Cancelling {k} for session {session.id}")
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                    except Exception:
                        logger.exception(f"[CLEAR] {k} exit error")
                    user_session.pop(k, None)

            # 3) 标记 mcp_session 需要关闭，但不在这里关闭
            # 因为 AsyncExitStack/TaskGroup 必须在创建它们的同一个任务中关闭
            # 真正的关闭会在下一次 on_chat_start 或 on_message 中执行
            if "mcp_session" in user_session:
                logger.info(f"[CLEAR] Marking mcp_session for closure (will be closed in main task chain) for session {session.id}")
                user_session["mcp_should_close"] = True
                # 只移除 mcp_tools，mcp_session 留到主流程中关闭
                user_session.pop("mcp_tools", None)
            
            # 4) 移除其他不需要的键，但保留 mcp_session 和 mcp_should_close
            # 这样 _close_mcp_session_if_needed 才能找到它们
            keys_to_remove = [k for k in user_session.keys() 
                             if k not in ("mcp_session", "mcp_should_close")]
            if keys_to_remove:
                logger.debug(f"[CLEAR] Removing keys from user_session: {keys_to_remove}")
            for k in keys_to_remove:
                user_session.pop(k, None)
            
            # 5) 如果 mcp_session 不存在，可以完全删除 user_session
            if "mcp_session" not in user_session:
                logger.info(f"[CLEAR] No mcp_session found, removing user_session completely for session {session.id}")
                user_sessions.pop(session.id, None)
            else:
                logger.info(f"[CLEAR] Retained mcp_session and mcp_should_close flag for session {session.id}")
        else:
            # 如果没有 user_session，直接删除
            logger.info(f"[CLEAR] No user_session found, removing session {session.id}")
            user_sessions.pop(session.id, None)

        await session.delete()

    if session.to_clear:
        logger.info(f"[DISCONNECT] Session marked for immediate clear: session_id={session.id}")
        await clear(sid)
    else:
        async def clear_on_timeout(_session_id):
            """
            Clear session after timeout using session_id instead of sid.
            This ensures cleanup works even after restore/reconnect changes the socket_id.
            """
            logger.info(f"[DISCONNECT] clear_on_timeout triggered for session_id={_session_id} after {config.project.session_timeout}s")
            await asyncio.sleep(config.project.session_timeout)
            await clear(_session_id)

        # timeout task 创建时保存引用，使用 session_id 而不是 sid
        # 这样即使 restore 后 sid 改变，清理任务仍然有效
        logger.info(f"[DISCONNECT] Creating clear_on_timeout task for session_id={session.id}, timeout={config.project.session_timeout}s")
        task = asyncio.create_task(clear_on_timeout(session.id))
        user_sessions.setdefault(session.id, {})["clear_task"] = task
        logger.info(f"[DISCONNECT] clear_on_timeout task created: {task}")


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
    logger.info(f"[PROCESS_MSG] Processing message for session_id={session.id}, socket_id={session.socket_id}")
    try:
        context = init_ws_context(session)
        logger.debug(f"[PROCESS_MSG] Sending task_start for session {session.id}")
        await context.emitter.task_start()
        message = await context.emitter.process_message(payload)
        logger.info(f"[PROCESS_MSG] Message processed: message_id={message.id if hasattr(message, 'id') else 'N/A'}")

        if config.code.on_message:
            logger.info(f"[PROCESS_MSG] Calling on_message callback for session {session.id}")
            # Close mcp_session if needed before calling on_message
            await _close_mcp_session_if_needed(session.id)
            await asyncio.sleep(0.001)
            await config.code.on_message(message)
            logger.info(f"[PROCESS_MSG] on_message callback completed for session {session.id}")
        else:
            logger.debug(f"[PROCESS_MSG] No on_message callback configured")
    except asyncio.CancelledError:
        logger.info(f"[PROCESS_MSG] Message processing cancelled for session {session.id}")
        pass
    except Exception as e:
        logger.exception(f"[PROCESS_MSG] Error processing message for session {session.id}: {e}")
        await ErrorMessage(
            author="Error", content=str(e) or e.__class__.__name__
        ).send()
    finally:
        logger.debug(f"[PROCESS_MSG] Sending task_end for session {session.id}")
        await context.emitter.task_end()
        logger.info(f"[PROCESS_MSG] Message processing completed for session {session.id}")


def _get_branch_id(step_row):
    """Extract branch_id from step metadata."""
    metadata = step_row.get("metadata")
    if not metadata:
        return "main"  # Default branch
    
    if isinstance(metadata, str):
        import json
        try:
            metadata = json.loads(metadata)
        except:
            return "main"
    
    return metadata.get("branch_id", "main")


def _filter_steps_by_branch(all_steps, branch_id, thread_metadata):
    """
    Filter steps to include:
    1. Fork point and earlier steps (from any branch, not inactive)
    2. Steps after fork point from current branch (not inactive)
    """
    import json
    
    # Find fork point for current branch (if it's a forked branch)
    fork_point_step_id = None
    if branch_id != "main":
        branches = thread_metadata.get("branches", [])
        for branch_info in branches:
            if branch_info.get("branch_id") == branch_id:
                fork_point_step_id = branch_info.get("fork_point")
                break
    
    # Find fork point step to get its createdAt
    fork_point_created_at = None
    if fork_point_step_id:
        for step in all_steps:
            if str(step.get("id")) == fork_point_step_id:
                fork_point_created_at = step.get("createdAt")
                break
    
    filtered_steps = []
    
    for step in all_steps:
        step_metadata = step.get("metadata", {})
        if isinstance(step_metadata, str):
            try:
                step_metadata = json.loads(step_metadata)
            except:
                step_metadata = {}
        if not isinstance(step_metadata, dict):
            step_metadata = {}
        
        step_branch_id = step_metadata.get("branch_id", "main")
        step_status = step_metadata.get("branch_status")
        step_id = str(step.get("id"))
        step_created_at = step.get("createdAt")
        
        # Check if step is before or at fork point
        is_before_fork = False
        if fork_point_created_at and step_created_at:
            is_before_fork = step_created_at <= fork_point_created_at
        elif fork_point_step_id and step_id == fork_point_step_id:
            is_before_fork = True
        
        # Include if:
        # 1. Before or at fork point (from any branch, not inactive) OR
        # 2. After fork point AND belongs to current branch AND not inactive
        if is_before_fork:
            # Before fork point: include from any branch (not inactive)
            if step_status != "inactive":
                filtered_steps.append(step)
        else:
            # After fork point: only include from current branch (not inactive)
            if step_branch_id == branch_id and step_status != "inactive":
                filtered_steps.append(step)
    
    # If no fork point found (main branch or branch not in branches list), 
    # just filter by current branch
    if not fork_point_step_id:
        filtered_steps = []
        for step in all_steps:
            step_metadata = step.get("metadata", {})
            if isinstance(step_metadata, str):
                try:
                    step_metadata = json.loads(step_metadata)
                except:
                    step_metadata = {}
            if not isinstance(step_metadata, dict):
                step_metadata = {}
            
            step_branch_id = step_metadata.get("branch_id", "main")
            step_status = step_metadata.get("branch_status")
            
            if step_branch_id == branch_id and step_status != "inactive":
                filtered_steps.append(step)
    
    return filtered_steps


async def fetch_steps_all_branches(data_layer, thread_id: str):
    """Fetch all steps including all branches."""
    from sqlalchemy import text
    sql = text("""
        SELECT
            s."id"       AS step_id,
            s."name"     AS step_name,
            s."parentId" AS step_parentid,
            s."input"    AS step_input,
            s."output"   AS step_output,
            s."type"     AS type,
            s."metadata" AS metadata,
            s."createdAt" AS "createdAt"
        FROM steps s
        WHERE s."threadId" = :thread_id
        ORDER BY s."createdAt" ASC
    """)
    
    async with data_layer.async_session() as session:
        result = await session.execute(sql, {"thread_id": thread_id})
        rows = result.mappings().all()
        return rows


async def fetch_steps(data_layer, thread_id: str):
    """Fetch steps for current branch only."""
    from sqlalchemy import text
    import json
    
    # Get current branch from thread metadata
    thread = await data_layer.get_thread(thread_id)
    if not thread or not isinstance(thread, dict):
        thread_metadata = {}
    else:
        thread_metadata = thread.get("metadata", {})
        if not thread_metadata:
            thread_metadata = {}
        elif isinstance(thread_metadata, str):
            try:
                thread_metadata = json.loads(thread_metadata)
            except:
                thread_metadata = {}
        elif not isinstance(thread_metadata, dict):
            thread_metadata = {}
    
    current_branch_id = thread_metadata.get("current_branch_id", "main") if isinstance(thread_metadata, dict) else "main"
    
    sql = text("""
        SELECT
            s."id"       AS step_id,
            s."name"     AS step_name,
            s."parentId" AS step_parentid,
            s."input"    AS step_input,
            s."output"   AS step_output,
            s."type"     AS type,
            s."metadata" AS metadata,
            s."createdAt" AS "createdAt"
        FROM steps s
        WHERE s."threadId" = :thread_id
        ORDER BY s."createdAt" ASC
    """)
    
    async with data_layer.async_session() as session:
        result = await session.execute(sql, {"thread_id": thread_id})
        rows = result.mappings().all()
        
        # Find fork point for current branch (if it's a forked branch)
        fork_point_step_id = None
        fork_point_created_at = None
        if current_branch_id != "main":
            branches = thread_metadata.get("branches", [])
            for branch_info in branches:
                if branch_info.get("branch_id") == current_branch_id:
                    fork_point_step_id = branch_info.get("fork_point")
                    break
        
        # Find fork point's createdAt if it exists
        if fork_point_step_id:
            for row in rows:
                if str(row.get("step_id")) == fork_point_step_id:
                    fork_point_created_at = row.get("createdAt")
                    break
        
        # Filter steps: include fork point and earlier steps (from any branch), 
        # plus current branch steps after fork point (non-inactive)
        filtered_rows = []
        for row in rows:
            branch_id = _get_branch_id(row)
            metadata = row.get("metadata")
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except:
                    metadata = {}
            
            step_id = str(row.get("step_id"))
            step_created_at = row.get("createdAt")
            step_status = metadata.get("branch_status")
            
            # Check if step is before or at fork point
            is_before_fork = False
            if fork_point_created_at and step_created_at:
                is_before_fork = step_created_at <= fork_point_created_at
            elif fork_point_step_id and step_id == fork_point_step_id:
                is_before_fork = True
            
            # Include if:
            # 1. Before or at fork point (from any branch, not inactive) OR
            # 2. After fork point AND belongs to current branch AND not inactive
            if is_before_fork:
                # Before fork point: include from any branch (not inactive)
                if step_status != "inactive":
                    filtered_rows.append(row)
            else:
                # After fork point: only include from current branch (not inactive)
                if branch_id == current_branch_id and step_status != "inactive":
                    filtered_rows.append(row)
        
        # If no fork point found (main branch or branch not in branches list), 
        # just filter by current branch
        if not fork_point_step_id:
            filtered_rows = []
            for row in rows:
                branch_id = _get_branch_id(row)
                metadata = row.get("metadata")
                if isinstance(metadata, str):
                    try:
                        metadata = json.loads(metadata)
                    except:
                        metadata = {}
                
                if branch_id == current_branch_id:
                    if metadata.get("branch_status") != "inactive":
                        filtered_rows.append(row)
        
        return filtered_rows

def _build_parent_map(steps_data):
    parent_map = {}
    for s in steps_data:
        sid = str(s.get("step_id"))
        pid = s.get("step_parentid")
        parent_map[sid] = str(pid) if pid is not None else None
    return parent_map

def _is_descendant(node_id: str, ancestor_id: str, parent_map: dict) -> bool:
    cur = node_id
    # 向上爬 parent 链
    while cur is not None:
        p = parent_map.get(cur)
        if p is None:
            return False
        if p == ancestor_id:
            return True
        cur = p
    return False

def find_subtree_end_index(steps_data, parent_id: str) -> int:
    parent_id = str(parent_id)
    parent_map = _build_parent_map(steps_data)

    parent_index = -1
    for i, s in enumerate(steps_data):
        if str(s.get("step_id")) == parent_id:
            parent_index = i
            break
    if parent_index == -1:
        return -1

    end = parent_index
    for i in range(parent_index + 1, len(steps_data)):
        sid = str(steps_data[i].get("step_id"))
        if _is_descendant(sid, parent_id, parent_map):
            end = i
    return end


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
    print("steps_data:", steps_data)
    steps_data = sorted(
        steps_data,
        key=lambda s: s.get("createdAt") or s.get("created_at") or 0
    )

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
            
            # Edit only updates content, doesn't delete subsequent messages or trigger regeneration
            return
    
    print(payload["message"])
    if not found:
        new_input = payload["message"].get("input")
        new_output = payload["message"].get("output")

        # 1) locate target step row
        target_row = None
        for s in steps_data:
            if str(s.get("step_id")) == target_id:
                target_row = s
                print("found target step:", s)
                break

        if not target_row:
            print("Not found target step id in steps_data:", target_id)
            logger.error(f"Edited target id {target_id} not found in steps_data.")
            return

        step_id = str(target_row.get("step_id"))
        step_name = target_row.get("step_name") or "step"
        step_parentid = target_row.get("step_parentid")
        step_parentid_str = str(step_parentid) if step_parentid is not None else None

        # 2) prepare Step object (the one being edited)
        orig_step = Step(id=step_id, name=step_name)
        orig_step.parent_id = step_parentid_str

        step_original_input = target_row.get("step_input")
        step_original_output = target_row.get("step_output")

        # 3) apply patch + capture original_content
        step_original_content = ""
        if new_input is not None and new_input != step_original_input:
            step_original_content = step_original_input or ""
            orig_step.input = new_input
            orig_step.output = None  # input changed => clear output
        elif new_output is not None and new_output != step_original_output:
            step_original_content = step_original_output or ""
            orig_step.input = step_original_input
            orig_step.output = new_output
        else:
            logger.error("No changes detected in input or output.")
            logger.info(f"Original input: {step_original_input}, New input: {new_input}")
            logger.info(f"Original output: {step_original_output}, New output: {new_output}")
            return

        await orig_step.update()

        original_content = step_original_content
        if not original_content:
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
        # Close mcp_session if needed before calling on_message
        await _close_mcp_session_if_needed(context.session.id)
        try:  
            await config.code.on_message(orig_message)  
        except asyncio.CancelledError:  
            pass  
        finally:  
            await context.emitter.task_end()

@sio.on("regenerate_message")  # pyright: ignore [reportOptionalCall]
async def regenerate_message(sid, payload: MessagePayload):
    """
    Handle a regenerate message request with fork support.
    
    Logic:
    1. Find the target message/step to regenerate
    2. Find the original user message that triggered it (fork point)
    3. Mark current branch steps after target (not including target) as inactive (soft delete)
    4. Target message itself is retained
    5. Create new branch
    6. Re-send the original user message to trigger regeneration
    """
    from chainlit.step import Step
    from chainlit.message import Message
    import uuid
    import json
    from datetime import datetime
    
    session = WebsocketSession.require(sid)
    context = init_ws_context(session)
    
    messages = chat_context.get()
    if messages is None:
        logger.error("No messages found in chat context.")
        return
    
    target_id = str(payload["message"]["id"])
    thread_id = session.thread_id
    data_layer = get_data_layer()
    
    # Get thread metadata to check current branch
    thread = await data_layer.get_thread(thread_id)
    if not thread:
        logger.error(f"Thread {thread_id} not found")
        return
    
    thread_metadata = thread.get("metadata", {})
    if isinstance(thread_metadata, str):
        try:
            thread_metadata = json.loads(thread_metadata)
        except:
            thread_metadata = {}
    
    # Create a copy of metadata to avoid modifying the original thread object
    if isinstance(thread_metadata, dict):
        thread_metadata = thread_metadata.copy()
    else:
        thread_metadata = {}
    
    current_branch_id = thread_metadata.get("current_branch_id", "main")
    
    # Get all steps data (including all branches)
    steps_data = await fetch_steps_all_branches(data_layer, thread_id)
    steps_data = sorted(
        steps_data,
        key=lambda s: s.get("createdAt") or s.get("created_at") or 0
    )
    
    # Filter to current branch only
    current_branch_steps = [
        s for s in steps_data 
        if _get_branch_id(s) == current_branch_id
    ]
    
    # Find target step in current branch
    target_step_row = None
    for s in current_branch_steps:
        if str(s.get("step_id")) == target_id:
            target_step_row = s
            break
    
    if not target_step_row:
        logger.error(f"Target step {target_id} not found in current branch.")
        return
    
    # Find fork point (the step before target)
    target_index = -1
    for i, s in enumerate(current_branch_steps):
        if str(s.get("step_id")) == target_id:
            target_index = i
            break
    
    if target_index == -1:
        logger.error(f"Target step {target_id} not found in sorted steps.")
        return
    
    # Find fork point (the step before target) - this is what we'll use to trigger regeneration
    fork_point_step_id = None
    fork_point_step = None
    if target_index > 0:
        # Fork point is the step before target
        fork_point_step = current_branch_steps[target_index - 1]
        fork_point_step_id = str(fork_point_step.get("step_id"))
    else:
        logger.error(f"No fork point found for target {target_id} (target is the first step).")
        return
    
    # Collect all steps before target to use as context
    # These steps will be used to regenerate the target step
    context_steps = current_branch_steps[:target_index]  # All steps before target
    context_step_ids = []  # List of step IDs before target
    
    # Collect step IDs from context steps
    for step in context_steps:
        step_id = str(step.get("step_id"))
        context_step_ids.append(step_id)
    
    # Use fork point step as the trigger message
    # Get content from fork point step (output or input)
    fork_point_content = fork_point_step.get("step_output") or fork_point_step.get("step_input") or ""
    if not fork_point_content:
        logger.error(f"Fork point step {fork_point_step_id} has no content.")
    
    # Create new branch
    new_branch_id = str(uuid.uuid4())
    fork_timestamp = datetime.now().isoformat()
    
    # Mark steps after target (not including target itself) in current branch as inactive
    # Target message itself will be retained
    steps_to_deactivate = current_branch_steps[target_index + 1:] if target_index + 1 < len(current_branch_steps) else []
    for s in steps_to_deactivate:
        logger.info(f"Deactivating step {s.get('step_id')} in branch {current_branch_id}, content: {s.get('step_output') or s.get('step_input') or ''}")
        step_id = str(s.get("step_id"))
        try:
            step = Step(id=step_id, name=s.get("step_name") or "step")
            step.parent_id = str(s.get("step_parentid")) if s.get("step_parentid") is not None else None
            
            # Get current metadata
            step_metadata = {}
            step_row_metadata = s.get("metadata")
            if step_row_metadata:
                if isinstance(step_row_metadata, str):
                    try:
                        step_metadata = json.loads(step_row_metadata)
                    except:
                        step_metadata = {}
                else:
                    step_metadata = step_row_metadata.copy()
            
            # Mark as inactive in current branch
            step_metadata["branch_status"] = "inactive"
            step_metadata["inactive_since"] = fork_timestamp
            step.metadata = step_metadata
            
            await step.update()
            logger.info(f"Deactivated step {step_id} in branch {current_branch_id}")
        except Exception as e:
            logger.warning(f"Failed to deactivate step {step_id}: {e}")
    
    # Update thread metadata with new branch
    # Note: thread_metadata is already a copy from above, safe to modify
    thread_metadata["current_branch_id"] = new_branch_id
    if "branches" not in thread_metadata:
        thread_metadata["branches"] = []
    # Create a copy of branches list to avoid modifying the original
    branches = thread_metadata["branches"].copy() if isinstance(thread_metadata.get("branches"), list) else []
    branches.append({
        "branch_id": new_branch_id,
        "forked_from": current_branch_id,
        "forked_at": fork_timestamp,
        "fork_point": fork_point_step_id,
        "target_step": target_id
    })
    thread_metadata["branches"] = branches
    
    await data_layer.update_thread(thread_id=thread_id, metadata=thread_metadata)
    
    # Emit branch_switched event to update UI dropdown
    await sio.emit("branch_switched", {
        "branch_id": new_branch_id,
        "thread_id": thread_id
    }, room=sid)
    
    # Reload thread to get messages for the new branch and update UI
    # Get thread and filter steps by current branch_id
    if data_layer and session.user:
        thread = await data_layer.get_thread(thread_id=thread_id)
        if thread:
            # Check if user is author
            author = thread.get("userIdentifier")
            user_is_author = author == session.user.identifier
            if user_is_author:
                # Filter steps by current branch_id (including fork point and earlier steps)
                all_steps = thread.get("steps", [])
                filtered_steps = _filter_steps_by_branch(all_steps, new_branch_id, thread_metadata)
                
                # Create a new thread dict with filtered steps
                filtered_thread = thread.copy()
                filtered_thread["steps"] = filtered_steps
                
                # Emit resume_thread event to reload messages for the new branch
                await context.emitter.resume_thread(filtered_thread)
    
    # Create message using fork point step to trigger regeneration
    # This message will contain metadata about context steps and target step
    orig_message = Message(content=fork_point_content)
    orig_message.id = fork_point_step_id
    orig_message.metadata = {}
    orig_message.metadata["regenerated"] = True
    orig_message.metadata["regenerated_from"] = target_id
    orig_message.metadata["branch_id"] = new_branch_id
    orig_message.metadata["forked_from"] = current_branch_id
    orig_message.metadata["fork_point"] = fork_point_step_id
    # Store all step IDs before target as context
    orig_message.metadata["context_step_ids"] = context_step_ids
    # Store target step ID
    orig_message.metadata["target_step_id"] = target_id
    
    await context.emitter.task_start()
    
    if config.code.on_message:
        # Close mcp_session if needed before calling on_message
        await _close_mcp_session_if_needed(context.session.id)
        try:
            await config.code.on_message(orig_message)
        except asyncio.CancelledError:
            pass
        finally:
            await context.emitter.task_end()

@sio.on("switch_branch")  # pyright: ignore [reportOptionalCall]
async def switch_branch(sid, payload: dict):
    """Switch to a different branch."""
    import json
    
    session = WebsocketSession.require(sid)
    context = init_ws_context(session)
    thread_id = session.thread_id
    branch_id = payload.get("branch_id")
    
    if not branch_id:
        logger.error("Missing branch_id in switch_branch request")
        return {"success": False, "error": "Missing branch_id"}
    
    data_layer = get_data_layer()
    thread = await data_layer.get_thread(thread_id)
    if not thread:
        logger.error(f"Thread {thread_id} not found")
        return {"success": False, "error": "Thread not found"}
    
    # Get metadata and create a copy to avoid modifying the original
    thread_metadata = thread.get("metadata", {})
    if isinstance(thread_metadata, str):
        try:
            thread_metadata = json.loads(thread_metadata)
        except:
            thread_metadata = {}
    
    # Create a copy of metadata to avoid modifying the original thread object
    if isinstance(thread_metadata, dict):
        thread_metadata = thread_metadata.copy()
    else:
        thread_metadata = {}
    
    # Verify branch exists
    branches = thread_metadata.get("branches", [])
    branch_exists = any(b.get("branch_id") == branch_id for b in branches) or branch_id == "main"
    
    if not branch_exists:
        logger.error(f"Branch {branch_id} not found in thread {thread_id}")
        return {"success": False, "error": "Branch not found"}
    
    # Update current branch in the copied metadata
    thread_metadata["current_branch_id"] = branch_id
    await data_layer.update_thread(thread_id=thread_id, metadata=thread_metadata)
    
    logger.info(f"Switched to branch {branch_id} in thread {thread_id}")
    
    # Reload thread to get messages for the new branch
    # Get thread and filter steps by current branch_id
    data_layer = get_data_layer()
    if data_layer and session.user:
        thread = await data_layer.get_thread(thread_id=thread_id)
        if thread:
            # Check if user is author
            author = thread.get("userIdentifier")
            user_is_author = author == session.user.identifier
            if user_is_author:
                # Update session metadata if needed
                metadata = thread.get("metadata") or {}
                if isinstance(metadata, str):
                    try:
                        metadata = json.loads(metadata)
                    except:
                        metadata = {}
                if metadata:
                    # Create a clean copy of metadata, excluding resource objects like mcp_session
                    # Only copy serializable data to avoid resource management issues
                    clean_metadata = {}
                    for key, value in metadata.items():
                        # Skip resource objects that shouldn't be copied
                        # These are managed separately in cl.user_session
                        if key in ["mcp_session", "mcp_tools"]:
                            continue
                        # Only copy serializable values (dict, list, str, int, float, bool, None)
                        if isinstance(value, (dict, list, str, int, float, bool, type(None))):
                            clean_metadata[key] = value
                        elif isinstance(value, list):
                            # For lists, only copy serializable items
                            clean_metadata[key] = [
                                item for item in value 
                                if isinstance(item, (dict, list, str, int, float, bool, type(None)))
                            ]
                    
                    # Only update user_sessions if clean_metadata is not empty
                    # Update existing dict instead of replacing to avoid triggering cleanup of old resources
                    if clean_metadata:
                        try:
                            # Get or create session dict
                            if session.id not in user_sessions:
                                user_sessions[session.id] = {}
                            
                            # Update existing dict instead of replacing to avoid triggering resource cleanup
                            existing_session = user_sessions[session.id]
                            if isinstance(existing_session, dict):
                                # Safe cleanup of mcp resources if they exist
                                # Use marking + _close_mcp_session_if_needed to avoid RuntimeError
                                if "mcp_session" in existing_session:
                                    logger.info(f"[SWITCH_BRANCH] Marking mcp_session for closure for session {session.id}")
                                    existing_session["mcp_should_close"] = True
                                    await _close_mcp_session_if_needed(session.id)
                                
                                # Ensure mcp_tools is also cleared if it wasn't by _close_mcp_session_if_needed
                                existing_session.pop("mcp_tools", None)
                                
                                # Update with clean metadata
                                existing_session.update(clean_metadata)
                            else:
                                # If existing_session is not a dict, replace it
                                user_sessions[session.id] = clean_metadata
                        except RuntimeError as e:
                            # Ignore RuntimeError from async generator cleanup
                            # This can happen when the session is being cleaned up
                            logger.debug(f"Could not update user_sessions (session may be closing): {e}")
                        except Exception as e:
                            # Catch any other exceptions during cleanup
                            logger.debug(f"Error updating user_sessions: {e}")
                    
                    if chat_profile := metadata.get("chat_profile"):
                        session.chat_profile = chat_profile
                    if chat_settings := metadata.get("chat_settings"):
                        session.chat_settings = chat_settings
                
                # Filter steps by current branch_id (including fork point and earlier steps)
                # get_thread returns all steps, we need to filter by branch_id
                all_steps = thread.get("steps", [])
                filtered_steps = _filter_steps_by_branch(all_steps, branch_id, thread_metadata)
                
                # Create a new thread dict with filtered steps
                filtered_thread = thread.copy()
                filtered_thread["steps"] = filtered_steps
                
                # Emit resume_thread event to reload messages for the current branch
                await context.emitter.resume_thread(filtered_thread)
    
    # Emit event to refresh UI
    await sio.emit("branch_switched", {
        "branch_id": branch_id,
        "thread_id": thread_id
    }, room=sid)
    
    return {"success": True, "branch_id": branch_id}


@sio.on("get_thread_metadata")  # pyright: ignore [reportOptionalCall]
async def get_thread_metadata(sid, payload: dict):
    """Get thread metadata including branch information."""
    import json
    
    session = WebsocketSession.require(sid)
    thread_id = payload.get("thread_id") or session.thread_id
    
    if not thread_id:
        return {"success": False, "error": "Missing thread_id"}
    
    data_layer = get_data_layer()
    thread = await data_layer.get_thread(thread_id)
    
    if not thread:
        return {"success": False, "error": "Thread not found"}
    
    thread_metadata = thread.get("metadata", {})
    if isinstance(thread_metadata, str):
        try:
            thread_metadata = json.loads(thread_metadata)
        except:
            thread_metadata = {}
    
    return {
        "success": True,
        "metadata": thread_metadata
    }


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


async def get_openai_history(thread_id: str, compressed: bool = False, cot_settings: Optional[str] = None):
    from typing import Any, Mapping, Optional, Dict, List

    data_layer = get_data_layer()
    thread = await data_layer.get_thread(thread_id)

    # 1) 全量 flatten（先不排序）
    flat: List[Dict[str, Any]] = []

    def collect_steps(steps: List[Dict[str, Any]]):
        for s in steps or []:
            # 跳过 wrapper steps，但继续收集其 children
            if s.get("name") in ["on_chat_start", "on_message", "on_audio_end"]:
                collect_steps(s.get("steps") or [])
                continue

            flat.append(s)
            collect_steps(s.get("steps") or [])

    collect_steps(thread.get("steps", []))

    # 2) 全局按 createdAt 排序（保证跨层顺序稳定）
    flat_sorted = sorted(
        [s for s in flat if s.get("createdAt")],
        key=lambda x: x["createdAt"]
    )

    # 3) 找到“最后一个 cot step”
    last_cot = None
    for s in flat_sorted:
        if s.get("type") == "cot":
            last_cot = s

    messages: List[Dict[str, str]] = []

    for s in flat_sorted:
        stype = s.get("type") or ""

        if stype in ["system_message", "user_message", "assistant_message"]:
            content = (s.get("output") or "")
            if stype == "assistant_message" and "**Selected:**" in content:
                continue
            messages.append({"role": stype.replace("_message", ""), "content": content})

        elif stype == "tool":
            if compressed:
                continue
            input_content = (s.get("input") or "")
            output_content = (s.get("output") or "")
            # 简单回放（如果你们没有 tool_call_id）
            messages.append({"role": "assistant", "content": input_content})
            messages.append({"role": "tool", "content": output_content})

        elif stype == "cot":
            if not compressed or s is last_cot:
                output_content = str(s.get("output") or "").strip()
                messages.append({"role": "assistant", "content": f"<think>{output_content}</think>"})
            else:
                plan = str(s.get("input") or "").strip()
                messages.append({"role": "assistant", "content": f"<think>{plan}</think>"})

    return messages

@sio.on("export_chat")
async def export_chat(sid, payload):
    from datetime import datetime

    thread_id = (payload or {}).get("threadId")
    if not thread_id:
        return {"success": False, "error": "Missing threadId"}

    # 可选参数：是否压缩、cot 设置
    compressed = bool((payload or {}).get("compressed", False))
    cot_settings = (payload or {}).get("cot_settings")  # Optional[str]

    try:
        # 直接用你的统一回放函数生成 OpenAI messages
        messages = await get_openai_history(
            thread_id=thread_id,
            compressed=compressed,
            cot_settings=cot_settings
        )

        export_obj = {
            "thread_id": thread_id,
            "exported_at": datetime.now().isoformat(),
            "compressed": compressed,
            "cot_settings": cot_settings,
            "messages": messages
        }

        import json
        json_content = json.dumps(export_obj, indent=2, ensure_ascii=False)

        suffix = "compressed" if compressed else "full"
        return {
            "success": True,
            "filename": f"chat_export_{thread_id[:8]}_{suffix}.json",
            "content": json_content
        }

    except Exception as e:
        return {"success": False, "error": str(e)}