export const SPV_LOG_NAME = "spvsdk";
export const SPV_DEFAULT_LOG = SPV_LOG_NAME;
export const SPV_FILE_NAME = "spvsdk.log";
//#define GetFunName() (std::string("<<< ") + (__FUNCTION__) + " >>>")

/* #define SPVLOG_DEBUG(...) SPDLOG_LOGGER_DEBUG(spdlog::get(SPV_DEFAULT_LOG), __VA_ARGS__)
#define SPVLOG_INFO(...)  SPDLOG_LOGGER_INFO(spdlog::get(SPV_DEFAULT_LOG), __VA_ARGS__)
#define SPVLOG_WARN(...)  SPDLOG_LOGGER_WARN(spdlog::get(SPV_DEFAULT_LOG), __VA_ARGS__)
#define SPVLOG_ERROR(...)  SPDLOG_LOGGER_ERROR(spdlog::get(SPV_DEFAULT_LOG), __VA_ARGS__)
#define SPVLOG_CRITICAL(...)  SPDLOG_LOGGER_CRITICAL(spdlog::get(SPV_DEFAULT_LOG), __VA_ARGS__)

#ifdef ARGUMENT_LOG_ENABLE
#define __va_first(first, ...) first
#define __va_rest(first, ...) __VA_ARGS__
#define ArgInfo(...) SPVLOG_INFO(__va_first(__VA_ARGS__, NULL), __va_rest(__VA_ARGS__, NULL))
#else
#define ArgInfo(...)
#endif */

/**
 * NOTE: for now this is a simple mapping to console.log.
 * Used to keep the same code style as the c++ spvsdk.
 * could be improved later for better log support (files, filters...)
 */
export class Log {
  /* static   registerMultiLogger(const std::string &path = ".") {
        if (spdlog::get(SPV_DEFAULT_LOG) != nullptr)
            return ;

#ifdef SPV_CONSOLE_LOG
#if defined(__ANDROID__)
        auto console_sink = std::make_shared<spdlog::sinks::android_sink_mt>("spvsdk");
#else
        auto console_sink = std::make_shared<spdlog::sinks::ansicolor_stdout_sink_mt>();
#endif
        console_sink->set_level(spdlog::level::trace);

        std::vector<spdlog::sink_ptr> sinks = {console_sink};
#else
        std::vector<spdlog::sink_ptr> sinks = {};
#endif

        std::string filepath = SPV_FILE_NAME;
        if (path != "") {
            filepath = path + "/" + SPV_FILE_NAME;
            auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(filepath, 1024*1024*50, 1);
            file_sink->set_level(spdlog::level::debug);
            sinks.push_back(file_sink);
        }

        auto logger = std::make_shared<spdlog::logger>(SPV_DEFAULT_LOG, sinks.begin(), sinks.end());
        spdlog::register_logger(logger);

        spdlog::get(SPV_DEFAULT_LOG)->set_pattern("%m-%d %T.%e %P %t %^%L%$ %n %v");
        spdlog::get(SPV_DEFAULT_LOG)->flush_on(spdlog::level::debug);
    } */

  public static setLevel() {
    // TODO
  }

  public static log(...args: any) {
    console.log.apply(console, [...args]);
  }

  public static warn(...args: any) {
    console.warn.apply(console, [...args]);
  }

  public static error(...args: any) {
    console.error.apply(console, [...args]);
  }

  public static info(...args: any) {
    console.log.apply(console, [...args]);
  }

  /*  template<typename Arg1, typename... Args>
     static inline void critical(const std::string &fmt, const Arg1 &arg1, const Args &... args) {
         spdlog::get(SPV_DEFAULT_LOG)->critical(fmt.c_str(), arg1, args...);
     }

     template<typename T>
     static inline void trace(const T &msg) {
         spdlog::get(SPV_DEFAULT_LOG)->trace(msg);
     }

     template<typename T>
     static inline void debug(const T &msg) {
         spdlog::get(SPV_DEFAULT_LOG)->debug(msg);
     }

    static inline void setLevel(spdlog::level::level_enum level) {
        spdlog::get(SPV_DEFAULT_LOG)->set_level(level);
    }

    static inline void setPattern(const std::string &fmt) {
        spdlog::get(SPV_DEFAULT_LOG)->set_pattern(fmt);
    }

    static inline void flush() {
        spdlog::get(SPV_DEFAULT_LOG)->flush();
    } */
}

export const warnLog = () => {
  console.warn("Warning! Unexpected code is been executed!");
};
