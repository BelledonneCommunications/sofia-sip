#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>

#define MSG_PUB_T struct sip_s
#include <sofia-sip/msg.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/su_log.h>

using namespace std;

static su_root_t* root = nullptr;

class MessageFactory {
public:
	MessageFactory(nta_agent_t* agent) : _agent{agent} {
		su_home_init(&_home);

		url_string_t request_uri{};
		strncpy(request_uri.us_str, "sip:127.0.0.1:5062;transport=tls", URL_MAXLEN);
		_requestLine = sip_request_create(&_home, sip_method_message, nullptr, &request_uri, nullptr);

		url_string_t from_uri{};
		strncpy(from_uri.us_str, "sips:127.0.0.1", URL_MAXLEN);
		_from = sip_from_create(&_home, &from_uri);

		url_string_t to_uri{};
		strncpy(to_uri.us_str, "sips:127.0.0.1:5062", URL_MAXLEN);
		_to = sip_to_create(&_home, &to_uri);

		_sep = sip_separator_create(&_home);

		string payloadData(1024, 'a');
		_payload = sip_payload_create(&_home, payloadData.c_str(), payloadData.size());
	}
	~MessageFactory() {
		su_home_deinit(&_home);
	}
	nta_agent_t* getAgent() const noexcept {return _agent;}
	msg_t* make() {
		su_home_t home{};
		su_home_init(&home);

		auto* callid = sip_call_id_create(&home, nullptr);
		auto* cseq = sip_cseq_create(&home, 20, sip_method_message, nullptr);

		auto* msg = nta_msg_create(_agent, 0);
		auto* sip_message = msg_object(msg);
		msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(_requestLine));
		msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(_from));
		msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(_to));
		msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(callid));
		msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(cseq));
		msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(_sep));
		msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(_payload));

		su_home_deinit(&home);
		return msg;
	}

private:
	nta_agent_t* _agent{nullptr};
	su_home_t _home{};
	sip_request_t* _requestLine{nullptr};
	sip_from_t* _from{nullptr};
	sip_to_t* _to{nullptr};
	sip_separator_t* _sep{nullptr};
	sip_payload_t* _payload{nullptr};
};

static int on_message_response(nta_outgoing_magic_t *magic, nta_outgoing_t *request, sip_t const *sip) noexcept {
	const auto& statusCode = sip->sip_status->st_status;
	const auto& phrase = sip->sip_status->st_phrase;
	cout << "\nReceiving response: " << statusCode << " " << phrase << "\n" << endl;

// 	if (root) su_root_break(root);

	return 0;
}

int main() {
	su_log_set_level(nullptr, SU_LOG_MAX);

	root = su_root_create(nullptr);

	url_string_t url{};
	strncpy(url.us_str, "sips:127.0.0.1", URL_MAXLEN);

	auto* agent = nta_agent_create(root, &url, nullptr, nullptr, TAG_END());
	MessageFactory factory{agent};

	auto* timer = su_timer_create(su_root_task(root), 10);
	su_timer_set_for_ever(timer,
		[](su_root_magic_t*, su_timer_t*, su_timer_arg_t* arg){
			auto* factory = static_cast<MessageFactory*>(arg);
			auto* msg = factory->make();
			auto* out_transaction = nta_outgoing_mcreate(factory->getAgent(), on_message_response, nullptr, nullptr, msg, TAG_END());
		}, &factory);

	su_root_run(root);

	// Cleaning
	nta_agent_destroy(agent);
	su_root_destroy(root);
	return 0;
}
